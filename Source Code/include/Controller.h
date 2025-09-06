#pragma once


#define ButtonUp		 1
#define ButtonDown		 2
#define ButtonLeft		 4
#define ButtonRight		 8
#define ButtonNorth		 16
#define ButtonSouth		 32
#define ButtonWest		 64
#define ButtonEast		 128
#define ButtonLeftStick  256
#define ButtonRightStick 512
#define ButtonL1		 1024
#define ButtonR1		 2048
#define ButtonL2		 4096
#define ButtonR2		 8192
#define ButtonSelect	 16384
#define ButtonStart		 32768


class Controller
{
private:
	unsigned int lastState;
	unsigned int newState;

public:
	Controller();
	~Controller();

	void ProcessState(unsigned int state);
	bool Active();

	unsigned int tap;
	unsigned int hold;
	unsigned int release;

	float Lx, Ly, Rx, Ry;
};

