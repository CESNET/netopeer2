#include "RequestHandler.hpp"
#include "SysrepoListener.hpp"

#include <unistd.h>

int main(int, char **) {
  SysrepoListener l;
  l.listen();

  RequestHandler handler(l);

  while (true) {
    pause();
  }
  return 0;
}
