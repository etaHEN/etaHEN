#pragma once

class Painter;

class Tetromino
{
public:
  enum Direction { LEFT = -1, RIGHT = 1 };
  enum Name { I, J, L, O, S, Z, T };
  // создание тетромины по имени
  Tetromino(Name);
  // рисование тетромины на рисовальщике Painter
  void draw(Painter &) const;
  // перемещение тетромины на dx, dy
  void move(int dx, int dy);
  // поворот тетромины по часовой стрелке или 
  // против часовой стрелке
  void rotate(Direction);
  bool map(int x, int y) const;
  int x() const { return x_; }
  int y() const { return y_; }
private:
  Name name_;
  int angel_;
  int x_;
  int y_;
};
