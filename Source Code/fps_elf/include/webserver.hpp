#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <cstring>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>

class SimpleHTTPServer {
private:
    int port;
    std::string root_dir;
    std::thread server_thread;
    bool running;

    std::string getMimeType(const std::string& path) {
        if (path.find(".html") != std::string::npos) return "text/html";
        if (path.find(".css") != std::string::npos) return "text/css";
        if (path.find(".js") != std::string::npos) return "application/javascript";
        if (path.find(".png") != std::string::npos) return "image/png";
        if (path.find(".jpg") != std::string::npos ||
            path.find(".jpeg") != std::string::npos) return "image/jpeg";
        if (path.find(".mp4") != std::string::npos) return "video/mp4";
        return "application/octet-stream";
    }

    long getFileSize(const std::string& path) {
        struct stat stat_buf;
        int rc = stat(path.c_str(), &stat_buf);
        return rc == 0 ? stat_buf.st_size : -1;
    }

    void parseRange(const std::string& range_header, long file_size,
        long& start, long& end) {
        start = 0;
        end = file_size - 1;

        if (range_header.empty()) return;

        std::string range = range_header.substr(6); // Remove "bytes="
        size_t dash_pos = range.find('-');

        if (dash_pos != std::string::npos) {
            std::string start_str = range.substr(0, dash_pos);
            std::string end_str = range.substr(dash_pos + 1);

            if (!start_str.empty()) start = std::stol(start_str);
            if (!end_str.empty()) end = std::stol(end_str);
        }

        if (end >= file_size) end = file_size - 1;
        if (start > end) start = end;
    }

    void sendResponse(int client_socket, const std::string& file_path,
        const std::string& range_header) {
        std::ifstream file(file_path, std::ios::binary);
        if (!file) {
            std::string response = "HTTP/1.1 404 Not Found\r\n"
                "Content-Length: 9\r\n\r\n"
                "Not Found";
            send(client_socket, response.c_str(), response.length(), 0);
            return;
        }

        long file_size = getFileSize(file_path);
        long start, end;
        parseRange(range_header, file_size, start, end);

        long content_length = end - start + 1;
        std::string mime_type = getMimeType(file_path);

        std::ostringstream response;

        if (range_header.empty()) {
            response << "HTTP/1.1 200 OK\r\n";
        }
        else {
            response << "HTTP/1.1 206 Partial Content\r\n";
            response << "Content-Range: bytes " << start << "-" << end
                << "/" << file_size << "\r\n";
        }

        response << "Content-Type: " << mime_type << "\r\n";
        response << "Content-Length: " << content_length << "\r\n";
        response << "Accept-Ranges: bytes\r\n";
        response << "Connection: close\r\n";
        response << "\r\n";

        std::string header = response.str();
        send(client_socket, header.c_str(), header.length(), 0);

        file.seekg(start);
        char buffer[8192];
        long bytes_to_send = content_length;

        while (bytes_to_send > 0 && file) {
            long chunk_size = std::min(bytes_to_send, (long)sizeof(buffer));
            file.read(buffer, chunk_size);
            long bytes_read = file.gcount();

            if (bytes_read > 0) {
                send(client_socket, buffer, bytes_read, 0);
                bytes_to_send -= bytes_read;
            }
            else {
                break;
            }
        }
    }

    void handleRequest(int client_socket) {
        char buffer[4096] = { 0 };
        recv(client_socket, buffer, sizeof(buffer), 0);

        std::string request(buffer);
        std::istringstream iss(request);
        std::string method, path, version;
        iss >> method >> path >> version;

        if (method != "GET") {
            std::string response = "HTTP/1.1 405 Method Not Allowed\r\n"
                "Content-Length: 18\r\n\r\n"
                "Method Not Allowed";
            send(client_socket, response.c_str(), response.length(), 0);
            return;
        }

        std::string range_header;
        size_t range_pos = request.find("Range: bytes=");
        if (range_pos != std::string::npos) {
            size_t end_pos = request.find("\r\n", range_pos);
            if (end_pos != std::string::npos) {
                range_header = request.substr(range_pos + 7,
                    end_pos - range_pos - 7);
            }
        }

        if (path == "/") path = "/index.html";
        std::string file_path = root_dir + path;

        sendResponse(client_socket, file_path, range_header);
    }

    void serverLoop() {
        int server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket < 0) {
            std::cerr << "Failed to create socket\n";
            return;
        }

        int opt = 1;
        setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port);

        if (bind(server_socket, (struct sockaddr*)&server_addr,
            sizeof(server_addr)) < 0) {
            std::cerr << "Failed to bind socket\n";
            close(server_socket);
            return;
        }

        if (listen(server_socket, 10) < 0) {
            std::cerr << "Failed to listen\n";
            close(server_socket);
            return;
        }

        running = true;

        while (running) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);

            int client_socket = accept(server_socket,
                (struct sockaddr*)&client_addr,
                &client_len);

            if (client_socket >= 0) {
                handleRequest(client_socket);
                close(client_socket);
            }
        }

        close(server_socket);
    }

    std::string getLocalIP() {
        std::string ip_address = "127.0.0.1";

        return ip_address;
    }
public:
    SimpleHTTPServer(int p, const std::string& root)
        : port(p), root_dir(root), running(false) {
    }

    ~SimpleHTTPServer() {
        stop();
    }

    void start() {
        if (!running) {
            server_thread = std::thread(&SimpleHTTPServer::serverLoop, this);
        }
    }

    void stop() {
        if (running) {
            running = false;
            if (server_thread.joinable()) {
                server_thread.join();
            }
            std::cout << "Server stopped.\n";
        }
    }

    bool isRunning() const {
        return running;
    }

    std::string getURL() {
        return "http://" + getLocalIP() + ":" + std::to_string(port);
    }
};