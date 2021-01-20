#include <string.h>

struct _pair {
  int first;
  int second;
};

struct _person {
  const char *name;
  char age;
};

struct _record {
  int a;
  struct _pair b;
  struct _person c;
};

struct _record r1 = {};
long long a1[256] = {};

int main(void) {
  if (r1.b.first == 0)
    r1.b.first = 1;
  else
    r1.b.first = 3;

  if (a1[42] == 0)
    a1[42] = 2;
  else
    a1[42] = 4;

  return r1.b.first + a1[42];
}