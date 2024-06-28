#include "session.h"
#include "../logger/logger.h"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <memory.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <resolv.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

#define TLS_SESSION_ID_OFFSET 43
#define SNI_EXTENSION_TYPE 0

using namespace std;
using namespace Rdg;

string Session::DNS_PREFIX = "_rdp._tcp.";
int Session::CONN_COUNT = 0;
int Session::BUFFER_SIZE = 4096;

Session::Session(int sockFd) {
  this->sockFd = sockFd;
  this->upstreamFd = 0;
  this->id = CONN_COUNT++;

  this->downstreamBuffer = new char[BUFFER_SIZE];
  this->buffer = new char[BUFFER_SIZE];
  this->slogpref = "[" + to_string(this->id) + "] ";

  this->x224RequestBuffer = new char[BUFFER_SIZE];
  this->terminated = false;
}

Session::~Session() {
  if (this->sockFd > 0)
    close(this->sockFd);
  if (this->upstreamFd > 0)
    close(this->upstreamFd);

  delete[] this->buffer;
  delete[] this->downstreamBuffer;
}

void Session::fork() {
  this->thread = std::thread(Session::sessionRoutine, this);
}

string Session::getRedirectionHost(int readBytes) {
  string host("");

  int offset, extensionsOffset, extensionsLength;

  // this message should be a TLS handshake

  if (buffer[0] != 0x16) {
    Logger::error(slogpref + "Malformed packet, expected TLS handshake");
    return host;
  }

  if (buffer[5] != 0x01) {
    Logger::error(slogpref +
                  "Malformed packet, expected Client Hello type handshake");
    return host;
  }

  // offset by session ID
  offset = TLS_SESSION_ID_OFFSET + buffer[TLS_SESSION_ID_OFFSET] + 1;
  // offset by cipher suites
  offset += 2 + (int)(unsigned char)buffer[offset] * 256 +
            (int)(unsigned char)buffer[offset + 1];
  // offset by compression methods
  offset += 1 + (int)(unsigned char)buffer[offset];

  extensionsOffset = offset + 2;
  extensionsLength = (int)(unsigned char)buffer[offset] * 256 +
                     (int)(unsigned char)buffer[offset + 1];

  if (extensionsLength + extensionsOffset > readBytes) {
    Logger::error(slogpref + "Insufficient bytes");
    return host;
  }

  for (int i = 0; i < extensionsLength;) {
    int extensionOffset = extensionsOffset + i;
    int extensionType = (int)(unsigned char)buffer[extensionOffset] * 256 +
                        (int)(unsigned char)buffer[extensionOffset + 1];
    int extensionLength =
        (int)(unsigned char)buffer[extensionOffset + 2] * 256 +
        (int)(unsigned char)buffer[extensionOffset + 3];

    if (extensionType != SNI_EXTENSION_TYPE) {
      // we care only SNI extension
      i += extensionLength;
      continue;
    }

    int extensionContentOffset = extensionOffset + 4;
    int serverListLength =
        (int)(unsigned char)buffer[extensionContentOffset] * 256 +
        (int)(unsigned char)buffer[extensionContentOffset + 1];

    for (int j = 0; j < serverListLength;) {
      int serverNameOffset = extensionContentOffset + 2 + j;
      int serverNameType = (int)buffer[serverNameOffset];
      int serverNameLength =
          (int)(unsigned char)buffer[serverNameOffset + 1] * 256 +
          (int)(unsigned char)buffer[serverNameOffset + 2];

      if (serverNameType != 0) {
        j += serverNameLength;
        break;
      }

      host = string(buffer + serverNameOffset + 3, serverNameLength);
      break;

      j += serverNameLength;
    }

    if (host.length() != 0)
      break;

    i += extensionLength;
  }

  return host;
}

unsigned char X224ConnectionResponse[] = {
    0x03, 0x00, 0x00, 0x13, // TPKT header
    0x0e, 0xd0, 0x00, 0x00, // X224 Ccf
    0x12, 0x34, 0x00,       // X224 Ccf ...
    /* RDP_NEG_RSP */
    0x02,                   // type
    0x0f,                   // flags
    0x08, 0x00,             // length
    0x02, 0x00, 0x00, 0x00, // Auth protocol
};

void Session::sessionRoutine(Session *session) {
  auto slogpref = session->slogpref;
  Logger::info(slogpref + "Session routine started");

  auto buffer = session->buffer;
  int readBytes = read(session->sockFd, buffer, BUFFER_SIZE), sentBytes,
      mcsRequestBytes;
  string host("");

  if (readBytes <= 0)
    goto done;

  session->x224RequestLength = readBytes;
  memcpy(session->x224RequestBuffer, session->buffer, readBytes);

  sentBytes = send(session->sockFd, X224ConnectionResponse, 19, 0);

  if (sentBytes <= 0)
    goto done;

  readBytes = read(session->sockFd, buffer, BUFFER_SIZE);

  if (readBytes <= 0)
    goto done;

  mcsRequestBytes = readBytes;

  host = session->getRedirectionHost(readBytes);

  if (host.length() == 0) {
    Logger::error("Unknown target host");
    goto done;
  }

  Logger::info(slogpref + "Requested redirection to host \"" + host + "\"");
  Logger::info(slogpref + "Resolving redirection target");

  if (session->resolveTarget(host) == 0) {
    Logger::error(slogpref + "Failed to resolve redirection target");
    goto done;
  }

  Logger::info(slogpref + "Upstream RDP connected");
  Logger::info(slogpref + "Replaying initial messages");

  sentBytes = send(session->upstreamFd, session->x224RequestBuffer,
                   session->x224RequestLength, 0);

  if (sentBytes <= 0)
    goto done;

  delete[] session->x224RequestBuffer;

  readBytes = read(session->upstreamFd, session->downstreamBuffer, BUFFER_SIZE);

  if (readBytes <= 0)
    goto done;

  sentBytes = send(session->upstreamFd, buffer, mcsRequestBytes, 0);

  if (sentBytes <= 0)
    goto done;

  Logger::info(slogpref + "Forwarding upcoming packets");

  pollfd downstreamFd;
  downstreamFd.fd = session->sockFd;
  downstreamFd.events = POLL_IN;

  pollfd upstreamFd;
  upstreamFd.fd = session->upstreamFd;
  upstreamFd.events = POLL_IN;

  int pollResult;

  while (1) {
    pollResult = poll(&upstreamFd, 1, 20);

    if (pollResult <= 0) {
      Logger::info(slogpref + "Upstream disconnected");
      goto done;
    }

    if (upstreamFd.revents & POLL_IN) {
      readBytes = read(session->upstreamFd, buffer, BUFFER_SIZE);
      if (readBytes <= 0)
        goto done;

      sentBytes = send(session->sockFd, buffer, readBytes, 0);
      if (sentBytes <= 0)
        goto done;
    }

    pollResult = poll(&downstreamFd, 1, 20);

    if (pollResult <= 0) {
      Logger::info(slogpref + "Downstream disconnected");
      goto done;
    }

    if (downstreamFd.revents & POLL_IN) {
      readBytes = read(session->sockFd, buffer, BUFFER_SIZE);
      if (readBytes <= 0)
        goto done;

      sentBytes = send(session->upstreamFd, buffer, readBytes, 0);
      if (sentBytes <= 0)
        goto done;
    }
  }

done:
  Logger::info(slogpref + "Closing session");
  session->terminated = true;
}

void Session::forwardRoutine(Session *session) {
  int readBytes, sentBytes;

  Logger::info(session->slogpref + "Forward routine started");

  while (1) {
    if (session->terminated)
      break;
    readBytes =
        read(session->upstreamFd, session->downstreamBuffer, BUFFER_SIZE);
    if (session->terminated)
      break;

    cout << "R"
         << " " << readBytes << endl;

    if (readBytes <= 0)
      break;

    sentBytes = send(session->sockFd, session->downstreamBuffer, readBytes, 0);

    if (sentBytes <= 0)
      break;
    cout << "S"
         << " " << sentBytes << endl;
  }

  Logger::info(session->slogpref + "Upstream closed connection");
  Logger::info(session->slogpref + "Closing session");
  session->terminated = true;
}
