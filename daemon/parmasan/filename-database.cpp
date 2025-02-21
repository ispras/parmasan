// SPDX-License-Identifier: MIT

#include "filename-database.hpp"
#include "utils/path-walker.hpp"

PS::EntryData* PS::FilenameDatabase::update_file(const std::string& pathname,
                                                 const PS::Entry& entry)
{
    PathWalker path_parser(pathname);

    File* file = get_root();
    std::optional<std::string_view> component;

    while ((component = path_parser.next_component())) {
        file = file->get_child(std::string(component.value()));
    }

    std::unique_ptr<EntryData>& entry_data = m_entries[entry];
    if (!entry_data)
        entry_data = std::make_unique<EntryData>();
    entry_data->last_known_file = file;

    return entry_data.get();
}
