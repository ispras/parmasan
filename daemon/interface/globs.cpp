// SPDX-License-Identifier: MIT

#include "globs.hpp"
#include <algorithm>
#include <deque>
#include <map>
#include <set>

// MARK: Algorithms

static void automaton_complete(Automaton& automaton)
{
    size_t trap_state = (size_t)-1;
    CharSet transitions;

    for (size_t i = 0; i < automaton.states.size(); i++) {
        if (i == trap_state)
            continue;

        auto& state = automaton.states[i];

        transitions.reset();
        for (const auto& transition : state.transitions) {
            transitions |= transition.chars;
        }

        if (!transitions.all()) {
            if (trap_state == (size_t)-1) {
                trap_state = automaton.add_state(false);
                automaton.add_transition(trap_state, trap_state, CharSet().set());
            }
            transitions.flip();
            automaton.add_transition(i, trap_state, transitions);
        }
    }
}

struct Superposition {
    std::set<size_t> states;
    bool is_final = false;
    mutable size_t id = 0;

    bool operator<(const Superposition& other) const
    {
        if (states.size() < other.states.size()) {
            return true;
        }
        if (states.size() > other.states.size()) {
            return false;
        }
        if (is_final < other.is_final) {
            return true;
        }
        if (is_final > other.is_final) {
            return false;
        }
        return states < other.states;
    }
};

struct SuperpositionTransition {
    CharSet chars{};
    Superposition target{};
};

struct SuperpositionTransitionSet {
    std::vector<SuperpositionTransition> transitions{};

    void add_transition(CharSet chars, size_t state, bool is_final)
    {
        for (size_t i = 0; i < transitions.size(); i++) {
            auto& transition_chars = transitions[i].chars;

            // transition_on and transition_off indicate which
            // bits of the transition should be affected by the
            // added transitions, and which of them shouldn't
            auto transition_on = chars & transition_chars;

            // If no bits are affected by the added transitions,
            // there is nothing to be done in this iteration.
            if (transition_on.none()) {
                continue;
            }

            // transition_off is calculated with inverted chars set.
            chars.flip();
            auto transition_off = chars & transition_chars;
            chars.flip();

            // If transition_off is not empty, the transition_chars
            // and char sets are overlapping. Split the current
            // transition in two halves, and only add new target for
            // the affected half.
            if (!transition_off.none()) {
                transitions.push_back({.chars = transition_off,
                                       .target = transitions[i].target});
                // Note that transition_chars is no longer valid
                // here, since transitions vector could have been
                // reallocated.
                transitions[i].chars = transition_on;
            }

            // Here, transition_chars is an element of disjunctive
            // association of initially given char set, so new
            // state can be safely added to each of such transitions.
            transitions[i].target.states.insert(state);
            transitions[i].target.is_final |= is_final;

            // Unset processed bits from the input char set
            chars ^= transition_on;
        }

        // If some chars remained unprocessed, it means that there were
        // no transitions for these specific characters.
        if (chars.none()) {
            return;
        }

        transitions.push_back({.chars = chars,
                               .target = Superposition{
                                   .states = {state},
                                   .is_final = is_final}});
    }
};

static size_t automaton_find_char_transition(const Automaton& automaton, size_t source_index,
                                             size_t target_index)
{
    auto& transitions = automaton.states[source_index].transitions;

    for (size_t i = 0; i < transitions.size(); i++) {
        auto& transition = transitions[i];
        if (transition.target_index == target_index) {
            return i;
        }
    }

    return -1;
}

static Automaton automaton_determine(const Automaton& automaton)
{
    Superposition start_superposition = {
        .states = {automaton.start_state_index},
        .is_final = automaton.states[automaton.start_state_index].is_final};

    Automaton new_automaton;
    new_automaton.add_state(start_superposition.is_final);

    std::set<Superposition> superpositions = {start_superposition};
    std::deque<Superposition> process_queue = {std::move(start_superposition)};
    SuperpositionTransitionSet superposition_transitions;

    while (!process_queue.empty()) {
        auto superposition = std::move(process_queue.front());
        process_queue.pop_front();

        // For each superposition, accumulate all transitions from it
        // and find potential next superpositions.
        for (auto& state_index : superposition.states) {
            auto& state = automaton.states[state_index];

            for (auto& transition : state.transitions) {
                auto target = transition.target_index;
                auto is_final = automaton.states[target].is_final;
                superposition_transitions.add_transition(transition.chars, target, is_final);
            }
        }

        // For any potential next superposition, add it to the
        // found superposition set, to the process queue, and to
        // the automaton.

        for (auto& transition : superposition_transitions.transitions) {
            size_t target_superposition_id = (size_t)-1;

            // If there was already such a transition
            auto it = superpositions.find(transition.target);
            if (it != superpositions.end()) {
                target_superposition_id = it->id;
            } else {
                new_automaton.add_state(transition.target.is_final);
                target_superposition_id = superpositions.size();
                transition.target.id = target_superposition_id;
                superpositions.insert(transition.target);
                process_queue.push_back(std::move(transition.target));
            }

            // Make sure not to make duplicated transitions
            size_t transition_index = automaton_find_char_transition(
                new_automaton, superposition.id, target_superposition_id);

            if (transition_index == (size_t)-1) {
                transition_index =
                    new_automaton.add_transition(superposition.id, target_superposition_id, {});
            }

            auto& automaton_transition =
                new_automaton.states[superposition.id].transitions[transition_index];
            automaton_transition.chars |= transition.chars;
        }

        superposition_transitions.transitions.clear();
    }

    return new_automaton;
}

struct AutomatonMinifierEquivalenceClass {
    size_t class_index;
    std::vector<size_t> transitions;

    bool operator<(const AutomatonMinifierEquivalenceClass& other) const
    {
        if (class_index != other.class_index) {
            return class_index < other.class_index;
        }
        return transitions < other.transitions;
    }
};

// Find the least set of atomically used char subsets
static std::vector<CharSet> automaton_get_charset_base(const Automaton& automaton)
{
    std::vector<CharSet> charset_base{CharSet().set()};

    for (const auto& state : automaton.states) {
        for (auto transition : state.transitions) {
            for (size_t i = 0; i < charset_base.size(); i++) {
                auto mask_on = charset_base[i] & transition.chars;
                if (mask_on.none())
                    continue;

                auto mask_off = charset_base[i] & ~transition.chars;
                if (mask_off.none())
                    continue;

                charset_base[i] = mask_on;
                charset_base.push_back(mask_off);
            }
        }
    }

    return charset_base;
}

static Automaton automaton_minify(const Automaton& automaton)
{
    size_t state_count = automaton.states.size();

    std::vector<size_t> new_class_indices(state_count);
    std::vector<size_t> class_indices(state_count);
    std::map<AutomatonMinifierEquivalenceClass, std::set<size_t>> equiv_classes;

    auto charset_base = automaton_get_charset_base(automaton);

    for (size_t i = 0; i < state_count; i++)
        class_indices[i] = automaton.states[i].is_final ? 1 : 0;

    AutomatonMinifierEquivalenceClass equiv_class;
    equiv_class.transitions.resize(charset_base.size());

    do {
        equiv_classes.clear();
        size_t max_class_index = 0;

        for (size_t i = 0; i < automaton.states.size(); i++) {
            auto state = automaton.states[i];
            equiv_class.class_index = class_indices[i];

            for (size_t charset_index = 0; charset_index < charset_base.size(); charset_index++) {
                auto& chars = charset_base[charset_index];

                for (auto transition : state.transitions) {
                    if ((transition.chars & chars).any()) {
                        size_t target_class = class_indices[transition.target_index];
                        equiv_class.transitions[charset_index] = target_class;
                        break;
                    }
                }
            }

            equiv_classes[equiv_class].insert(i);
        }

        for (auto& [eq_class, states] : equiv_classes) {
            for (size_t state : states)
                new_class_indices[state] = max_class_index;

            max_class_index++;
        }

        std::swap(class_indices, new_class_indices);
    } while (class_indices != new_class_indices);

    Automaton result;

    result.states.resize(equiv_classes.size());

    for (auto& [eq_class, states] : equiv_classes) {
        for (size_t old_state : states) {
            if (automaton.states[old_state].is_final)
                result.states[eq_class.class_index].is_final = true;

            if (automaton.start_state_index == old_state)
                result.start_state_index = (eq_class.class_index);
        }

        for (size_t i = 0; i < eq_class.transitions.size(); i++) {
            auto& transition = eq_class.transitions[i];

            size_t transition_index = automaton_find_char_transition(
                result, eq_class.class_index, transition);

            if (transition_index == (size_t)-1) {
                transition_index = result.add_transition(eq_class.class_index, transition, {});
            }

            auto& automaton_transition = result.states[eq_class.class_index]
                                             .transitions[transition_index];
            automaton_transition.chars |= charset_base[i];
        }
    }

    return result;
}

static void automaton_remove_unreachable_states(Automaton& automaton)
{
    std::vector<bool> reachable(automaton.states.size(), false);
    reachable[automaton.start_state_index] = true;

    std::vector<size_t> current_states = {automaton.start_state_index};

    while (!current_states.empty()) {
        size_t state_index = current_states.back();
        current_states.pop_back();

        for (auto& transition : automaton.states[state_index].transitions) {
            if (!reachable[transition.target_index]) {
                reachable[transition.target_index] = true;
                current_states.push_back(transition.target_index);
            }
        }
    }

    for (int i = (int)reachable.size() - 1; i >= 0; i--) {
        if (!reachable[i])
            automaton.remove_state(i);
    }
}

static void automaton_epsilon_connect(Automaton& automaton, size_t from, size_t to)
{
    // Connect two states with an epsilon transition, without
    // adding any epsilon transitions.

    if (from == to)
        return;

    if (automaton.states[to].is_final)
        automaton.states[from].is_final = true;

    auto& to_transitions = automaton.states[to].transitions;

    for (auto& transition : to_transitions) {
        if (!transition.chars.none())
            automaton.add_transition(from, transition.target_index, transition.chars);
    }
}

static void automaton_build_epsilon_closure(Automaton& automaton, size_t state,
                                            std::set<size_t>& epsilon_closure)
{
    if (epsilon_closure.count(state))
        return;

    epsilon_closure.insert(state);

    auto& transitions = automaton.states[state].transitions;

    for (auto& transition : transitions) {
        if (transition.chars.none())
            automaton_build_epsilon_closure(automaton, transition.target_index, epsilon_closure);
    }
}

static void automaton_remove_epsilon_transitions(Automaton& automaton)
{
    std::set<size_t> epsilon_closure;

    auto& states = automaton.states;
    for (size_t i = 0; i < states.size(); i++) {
        epsilon_closure.clear();
        automaton_build_epsilon_closure(automaton, i, epsilon_closure);

        for (auto closure_state_index : epsilon_closure) {
            if (closure_state_index == i)
                continue;

            automaton_epsilon_connect(automaton, i, closure_state_index);
        }

        auto& transitions = automaton.states[i].transitions;
        transitions.erase(std::remove_if(transitions.begin(), transitions.end(),
                                         [](AutomatonTransition& transition) {
                                             return transition.chars.none();
                                         }),
                          transitions.end());
    }
}

// Adds A2 to A1 using logical and
Automaton automaton_join(Automaton& a1, const Automaton& a2, bool logical_and)
{
    size_t old_start = a1.start_state_index;
    a1.start_state_index = a1.add_state(logical_and);

    size_t offset = a1.states.size();

    // Add states of the second automaton and move the target indices
    // of their transitions to match the new positions of new states.

    a1.states.insert(a1.states.end(), a2.states.begin(), a2.states.end());

    for (size_t i = offset; i < a1.states.size(); i++) {
        for (auto& transition : a1.states[i].transitions) {
            transition.target_index += offset;
        }
    }

    // The double-inversion turns logical 'a1 || b1' into !(!a1 || !b1) = a1 && b1.
    // At this point, a1 and a2 are both located in a1, but their states are not
    // yet merged in a single deterministic automaton, so inverting the entire
    // a1 achieves the (!a1 || !a2) step. (although it's not that simple for the
    // start state)
    if (logical_and)
        a1.invert();

    // Connect the newly created start state with start states of a1 and a2
    // with an epsilon transitions. automaton_epsilon_connect is used here
    // to avoid calling expensive automaton_remove_epsilon_transitions
    // procedure.
    automaton_epsilon_connect(a1, a1.start_state_index, old_start);
    automaton_epsilon_connect(a1, a1.start_state_index, a2.start_state_index + offset);
    automaton_remove_unreachable_states(a1);

    a1 = automaton_determine(a1);
    a1 = automaton_minify(a1);

    if (logical_and)
        a1.invert();

    return a1;
}

// MARK: Automaton implementation

Automaton Automaton::from_glob(std::string_view input)
{
    Automaton automaton;
    size_t last_index = automaton.add_state(false);

    bool escape = false;
    for (auto c : input) {
        if (!escape && c == '*') {
            size_t loop_start = automaton.add_state(false);
            size_t loop_end = automaton.add_state(false);
            size_t exit = automaton.add_state(false);

            automaton.add_transition(loop_start, loop_end, CharSet().set());
            automaton.add_transition(last_index, loop_start, {});
            automaton.add_transition(loop_end, loop_start, {});
            automaton.add_transition(loop_start, exit, {});

            last_index = exit;
        } else if (!escape && c == '?') {
            size_t next_index = automaton.add_state(false);
            automaton.add_transition(last_index, next_index, CharSet().set());
            last_index = next_index;
        } else if (!escape && c == '\\') {
            escape = true;
        } else {
            escape = false;

            size_t next_index = automaton.add_state(false);
            automaton.add_transition(last_index, next_index, CharSet().set((unsigned char)c));
            last_index = next_index;
        }
    }

    size_t finish_index = automaton.add_state(true);
    automaton.add_transition(last_index, finish_index, {});

    automaton_remove_epsilon_transitions(automaton);
    automaton_remove_unreachable_states(automaton);
    automaton_complete(automaton);
    automaton = automaton_determine(automaton);
    automaton = automaton_minify(automaton);

    return automaton;
}

size_t Automaton::add_state(bool is_final)
{
    states.push_back({.is_final = is_final, .transitions = {}});
    return states.size() - 1;
}

void Automaton::remove_state(size_t state_index)
{
    // Remove state and all transitions connected to it

    for (size_t i = 0; i < states.size(); i++) {
        auto& state = states[i];
        for (size_t j = 0; j < state.transitions.size(); j++) {
            size_t target_index = state.transitions[j].target_index;
            if (target_index == state_index) {
                remove_transition(i, j);
                j--;
            } else if (target_index > state_index) {
                state.transitions[j].target_index--;
            }
        }
    }

    if (start_state_index == state_index) {
        start_state_index = 0;
    } else if (start_state_index > state_index) {
        start_state_index--;
    }

    states.erase(states.begin() + state_index);
}

size_t Automaton::add_transition(size_t from, size_t to, const CharSet& regex)
{
    auto& transitions = states[from].transitions;
    transitions.push_back(AutomatonTransition{regex, to});
    return transitions.size() - 1;
}

void Automaton::remove_transition(size_t state_index, size_t transition_index)
{
    auto position = states[state_index].transitions.begin() + transition_index;
    states[state_index].transitions.erase(position);
}

Automaton& Automaton::invert()
{
    for (auto& state : states)
        state.is_final = !state.is_final;

    return *this;
}

CompiledAutomaton Automaton::compile() const
{
    CompiledAutomaton result;
    result.states.resize(states.size());

    for (size_t i = 0; i < states.size(); i++) {
        auto& state = states[i];

        size_t compiled_index = i;
        if (i < start_state_index)
            compiled_index++;
        if (i == start_state_index)
            compiled_index = 0;

        result.states[compiled_index].is_final = state.is_final;

        for (auto& transition : state.transitions) {
            for (int ch = 0; ch <= 255; ch++) {
                if (!transition.chars[ch]) {
                    continue;
                }

                size_t compiled_target_index = transition.target_index;
                if (transition.target_index < start_state_index)
                    compiled_target_index++;
                if (transition.target_index == start_state_index)
                    compiled_target_index = 0;

                result.states[compiled_index].jump_table[ch] = compiled_target_index;
            }
        }
    }

    return result;
}

Automaton Automaton::null()
{
    Automaton result;
    result.start_state_index = result.add_state(false);
    result.add_transition(0, 0, CharSet().set());
    return result;
}
