
#include "utils.hpp"

void get_folder_name(const std::string& path, int& index, std::string& folder_name) {
    while (path[index] != '/' && path[index] != '\0') {
        folder_name.push_back(path[index++]);
    }
    while (path[index] == '/')
        index++;
}
