#ifndef RDG_LOGGER_LOGGER_H
#define RDG_LOGGER_LOGGER_H

#include <iostream>
#include <string>

using namespace std;

namespace Rdg {
class Logger {
private:
  static void log(const string &message, ostream &stream, int level);

public:
  static void error(const string &message);
  static void warn(const string &message);
  static void info(const string &message);
};
} // namespace Rdg

#endif // RDG_LOGGER_LOGGER_H