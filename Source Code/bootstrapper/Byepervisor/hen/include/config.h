#ifndef CONFIG_H
#define CONFIG_H

/*
 * Enable debug logging via TCP connection to PC
 */
#define PC_DEBUG_ENABLED                    1

/*
 * PC IP address for debug logging
 */
#define PC_DEBUG_IP                         "10.0.0.143"

/*
 * PC IP port for debug logging
 */
#define PC_DEBUG_PORT                       5655

/*
 * TCP port to run the RPC server on
 */
#define RPC_TCP_PORT                        9002

#endif // CONFIG_H