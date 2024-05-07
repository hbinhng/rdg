#include "./rdg-server/rdg-server.h"

#include <iostream>

using namespace std;
using namespace Rdg;

int main() {
  auto server = new RdgServer("0.0.0.0", 3389);
  server->run();
}