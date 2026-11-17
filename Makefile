# Builds and runs the portable library's tests and example.
#
#   make            build everything
#   make test       run the vectors in vectors/ against lib/
#   make example    run the Bitflash example
#   make CXX=clang++ test

CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion
BUILD ?= build

ifeq ($(OS),Windows_NT)
EXE := .exe
endif

LIB_SRC := lib/everpool.cpp
LIB_HDR := lib/everpool.h lib/examples/bitflash.h
TEST_BIN := $(BUILD)/everpool-test$(EXE)
EXAMPLE_BIN := $(BUILD)/pool-zero$(EXE)

.PHONY: all test example clean

all: $(TEST_BIN) $(EXAMPLE_BIN)

$(BUILD):
	mkdir -p $(BUILD)

$(TEST_BIN): lib/test.cpp $(LIB_SRC) $(LIB_HDR) | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ lib/test.cpp $(LIB_SRC)

$(EXAMPLE_BIN): lib/examples/pool_zero.cpp $(LIB_SRC) $(LIB_HDR) | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ lib/examples/pool_zero.cpp $(LIB_SRC)

test: $(TEST_BIN)
	./$(TEST_BIN) vectors

example: $(EXAMPLE_BIN)
	./$(EXAMPLE_BIN)

clean:
	rm -rf $(BUILD)
