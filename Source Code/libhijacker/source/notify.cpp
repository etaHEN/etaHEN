#include "notify.hpp"

void printf_notification(const char *fmt, ...)
{
	OrbisNotificationRequest noti_buffer{};

	va_list args{};
	va_start(args, fmt);
	int len = vsnprintf(noti_buffer.message, sizeof(noti_buffer.message), fmt, args);
	va_end(args);

	// these dont do anything currently
	// that or the structure has changed
	// lets just copy messages for now
	/*
	noti_buffer.type = 0;
	noti_buffer.unk3 = 0;
	noti_buffer.use_icon_image_uri = 0;
	noti_buffer.target_id = -1;
	*/
	// trim newline
	if (noti_buffer.message[len - 1] == '\n')
	{
		noti_buffer.message[len - 1] = '\0';
	}
	printf("Sent notification: 0x%08x with message:\n%s\n", sceKernelSendNotificationRequest(0, (OrbisNotificationRequest *)&noti_buffer, sizeof(noti_buffer), 0), noti_buffer.message);
}