#include "ft_ssl_md5.h"

void	handle_des(char *message, t_options *opts, char **av)
{
	(void)message;
	(void)opts;
	t_pbkdf df;

	if (!(init_pbkdf(&df, opts, av)))
		return;
	gen_key(&df, opts, message);
}
