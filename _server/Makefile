CC := g++
CFLAGS := -Wall -Wextra -std=c++17
SRCDIR := server
BUILDDIR := ../build

SRCS := main.cpp Reciever.cpp
OBJS := $(SRCS:$(SRCDIR)/%.cpp=$(BUILDDIR)/%.o)
TARGET := server

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $(BUILDDIR)/$@

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILDDIR)/*.o $(BUILDDIR)/$(TARGET)