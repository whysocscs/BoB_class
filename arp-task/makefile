CXX = g++
CXXFLAGS = -Wall -g
LIBS = -lpcap

TARGET = arp_task

SRCS = main.cpp mac_addr.cpp arp.cpp
OBJS = $(SRCS:.cpp=.o)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)
