#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    const char *name = strrchr(argv[0], '/');
    bool isolated = false;
    bool test = false;
    bool reload = false;

    name = name == NULL ? argv[0] : name + 1;
    for (int index = 1; index < argc; ++index) {
        if (strcmp(argv[index], "-p") == 0) isolated = true;
        if (strcmp(argv[index], "-t") == 0) test = true;
        if (strcmp(argv[index], "reload") == 0) reload = true;
    }
    if (strstr(name, "fail-live-test") != NULL && test && !isolated) return EXIT_FAILURE;
    if (strstr(name, "fail-reload") != NULL && reload) return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
