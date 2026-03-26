#pragma once
#include <unordered_map>
#include <memory>
#include <string>
#include <vector>
#include <mutex>
#ifndef _WIN32
#include <sys/eventfd.h>
#include <unistd.h>
#endif
#include "snap.hpp"

namespace librats {

class SnapLocalBypass {
public:
    static SnapLocalBypass& instance() {
        static SnapLocalBypass inst;
        return inst;
    }

    bool is_snap(int fd) {
        std::lock_guard<std::mutex> lock(mutex_);
        return links_.find(fd) != links_.end();
    }

    int create_link(const std::string& host, int port, bool is_server) {
        // We use eventfd as a "dummy" socket handle that is valid in Linux
#ifdef _WIN32
        // Windows dummy handle (not a real socket but we'll treat it as one)
        int fd = 0x544E4150; // 'SNAP' in hex
#else
        int fd = eventfd(0, EFD_NONBLOCK);
#endif
        std::string uri = "shm://librats_" + std::to_string(port);
        
        std::lock_guard<std::mutex> lock(mutex_);
        links_[fd] = snap::connect<std::vector<uint8_t>>(uri);
        return fd;
    }

    int send(int fd, const std::vector<uint8_t>& data) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = links_.find(fd);
        if (it != links_.end()) {
            return it->second->send(data) ? (int)data.size() : -1;
        }
        return -1;
    }

    std::vector<uint8_t> recv(int fd, size_t max_size) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = links_.find(fd);
        if (it != links_.end()) {
            std::vector<uint8_t> data;
            if (it->second->recv(data)) {
                return data;
            }
        }
        return {};
    }

    void close(int fd) {
        std::lock_guard<std::mutex> lock(mutex_);
        links_.erase(fd);
#ifndef _WIN32
        ::close(fd);
#endif
    }

private:
    SnapLocalBypass() = default;
    std::mutex mutex_;
    std::unordered_map<int, std::unique_ptr<snap::ILink<std::vector<uint8_t>>>> links_;
};

} // namespace librats
