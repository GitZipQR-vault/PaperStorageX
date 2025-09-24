CXX ?= g++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra
LDFLAGS ?= -lcrypto

BIN := paperx
SRC := src/main.cpp
HDR := src/lodepng.h src/sha256.h

all: $(BIN)

$(BIN): $(SRC) $(HDR)
	$(CXX) $(CXXFLAGS) -o $@ $(SRC) $(LDFLAGS)

clean:
	rm -f $(BIN)

.PHONY: all clean
