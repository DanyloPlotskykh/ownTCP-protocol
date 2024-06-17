# Имя библиотеки
TARGET = libtools.a

# Директории
INCDIR = include
SRCDIR = src
BUILDDIR = ../build

# Компилятор и флаги
CXX = g++
CXXFLAGS = -Wall -I$(INCDIR) -c

# Список исходных файлов
SRCS = $(wildcard $(SRCDIR)/*.cpp)

# Преобразование списка исходных файлов в список объектных файлов
OBJS = $(patsubst $(SRCDIR)/%.cpp, $(BUILDDIR)/%.o, $(SRCS))

# Цель по умолчанию
all: $(BUILDDIR)/$(TARGET)

# Сборка статической библиотеки
$(BUILDDIR)/$(TARGET): $(OBJS)
	ar rcs $@ $^

# Сборка объектных файлов
$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -o $@ $<

# Создание директории build, если она не существует
$(BUILDDIR):
	mkdir -p $(BUILDDIR)

# Правило для очистки
clean:
	rm -f $(BUILDDIR)/*.o $(BUILDDIR)/$(TARGET)

.PHONY: all clean
