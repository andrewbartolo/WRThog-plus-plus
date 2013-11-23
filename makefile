FILES = wrthog.cc
OUT_BIN = wrthog
CXXFLAGS = -std=c++11 -Wall -pedantic

build: $(FILES)
				$(CXX) $(CXXFLAGS) -Ofast -o $(OUT_BIN) $(FILES) -lcurl -pthread

clean:
				rm -f *.o wrthog

rebuild: clean build

debug: $(FILES)
				$(CXX) $(CXXFLAGS) -g -o $(OUT_BIN) $(FILES) -lcurl -pthread
