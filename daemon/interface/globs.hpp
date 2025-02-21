// SPDX-License-Identifier: MIT

#pragma once

#include <bitset>
#include <string>
#include <vector>

typedef std::bitset<256> CharSet;

struct CompiledAutomatonState {
    size_t jump_table[256]{};
    bool is_final = false;
};

struct CompiledAutomaton {
    std::vector<CompiledAutomatonState> states;
};

struct AutomatonTransition {
    CharSet chars{};
    size_t target_index = (size_t)-1;
};

struct AutomatonState {
    bool is_final = false;
    std::vector<AutomatonTransition> transitions;
};

struct Automaton {
    std::vector<AutomatonState> states;
    size_t start_state_index = 0;

    Automaton() = default;
    Automaton(const Automaton& copy) = default;
    Automaton(Automaton&& move) noexcept = default;

    Automaton& operator=(Automaton&& move) = default;
    Automaton& operator=(const Automaton& copy) = default;

    static Automaton null();
    static Automaton from_glob(std::string_view input);

    size_t add_state(bool is_final);
    void remove_state(size_t i);

    size_t add_transition(size_t from, size_t to, const CharSet& regex);
    void remove_transition(size_t state_index, size_t transition_index);

    Automaton& invert();

    CompiledAutomaton compile() const;
};

Automaton automaton_join(Automaton& a1, const Automaton& a2, bool logical_and = true);
