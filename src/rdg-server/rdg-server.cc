#include "rdg-server.h"
#include "../logger/logger.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <string>
#include <sys/socket.h>

using namespace std;
using namespace Rdg;

RdgServer::RdgServer(string host, int port) {
  if (inet_pton(AF_INET, host.c_str(), &(this->address.sin_addr)) == 0) {
    Logger::error("Invalid bind address");
    exit(EXIT_FAILURE);
  }

  this->sockFd = socket(AF_INET, SOCK_STREAM, 0);

  if (this->sockFd == 0) {
    Logger::error("Cannot create socket");
    exit(EXIT_FAILURE);
  }

  int opt = 1;

  if (setsockopt(this->sockFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
    Logger::error("Cannot set socket options");
    exit(EXIT_FAILURE);
  }

  this->address.sin_port = htons(port);
  this->address.sin_family = AF_INET;

  if (bind(this->sockFd, (struct sockaddr *)&this->address,
           sizeof(this->address)) < 0) {
    Logger::error("Cannot bind to specified address");
    exit(EXIT_FAILURE);
  }

  if (listen(this->sockFd, 1024) < 0) {
    Logger::error("Cannot listen on specified address and port");
    exit(EXIT_FAILURE);
  }

  Logger::info("RDG server is listening on " + host + ":" + to_string(port));
}

void RdgServer::run() {
  this->mainThread = new thread(RdgServer::mainThreadRoutine, this);

  this->mainThread->join();
}

int RdgServer::getSockFd() { return this->sockFd; }

void RdgServer::mainThreadRoutine(RdgServer *rdg) {
  Logger::info("RDG main thread started, accepting new connections");

  while (1) {
    struct sockaddr_in clientAddress;
    socklen_t clientAddressLen = sizeof(clientAddress);

    auto fd = accept(rdg->getSockFd(), (struct sockaddr *)&clientAddress,
                     &clientAddressLen);

    Logger::info("New client connected");

    auto session = new Session(fd);

    session->fork();
  }
}
