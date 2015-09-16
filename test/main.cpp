/*
 * main.cpp:
 *
 * Copyright (c) 2015 Masashi Fujita
 */
#define CATCH_CONFIG_RUNNER 1
#include <catch.hpp>

int main (int argc, char **argv) {
    int result = Catch::Session().run (argc, argv) ;

    return result ;
}
