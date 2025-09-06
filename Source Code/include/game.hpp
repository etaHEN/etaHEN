#pragma once
#include "tetromino.hpp"
#include "well.hpp"

class Painter;

class Game
{
public:
  enum Direction { UP, DOWN, LEFT, RIGHT };
  Game();
  void draw(Painter &);
  void tick();
  void restart();
  void keyEvent(Direction);
private:
  Well well_;
  Tetromino tetromino_;
};
