/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/11 18:00:41 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/15 17:40:18 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

t_cypher_cmd	g_cyph[] =
{
	{"base64", base64},
	{"des", handle_des},
//	{"des-ecb", handle_ecb},
//	{"des-cbc", handle_cbc},
	{0}
};
/*
t_digest_cmd	g_cmd[] =
{
	{"md5", handle_md5},
	{"sha256", handle_256},
	{"sha224", handle_224},
	{"sha1", handle_sha1},
	{"base64", base64_encode},
	{0}
};
*/
static int				get_cypher(char *cmd, t_options *opts)
{
	int i;

	i = 0;
	while (g_cyph[i].cmd)
	{
		if (!(ft_strncmp(g_cyph[i].cmd, cmd, ft_strlen(g_cyph[i].cmd))))
		{
			if (!(invalid_opts(cmd, opts)))
				return (0);
			else
				return (i);
		}
	//	else
	//	{
	//		ft_printf("ft_ssl: Error: '%s' is an invalid command.\n", cmd);
	//	}
		i++;
	}
	return (-1);
}

int				parse_args(char **av, char *buf, t_options opts, int i)
{
	int	j;

	while (g_cyph[++i].cmd)
		if (!(ft_strncmp(g_cyph[i].cmd, av[1], ft_strlen(g_cyph[i].cmd))))
		{
			j = 1;
			//if (!(invalid_opts(av[1], &opts)))
			//	return (0);
			if (opts.is_stdin)
				g_cyph[i].f(buf, &opts, av);
			else
				g_cyph[i].f(av[opts.pass + 2], &opts, av);
			/*
			while (av[opts.n_opts + ++j])
			{
				opts.is_stdin = 0;
			//	if (av[opts.n_opts + j][0] == '-')
			//		return (wrong_format(g_cyph[i].cmd, &av[opts.n_opts + j]));
				if ((buf = get_file(av[opts.n_opts + j])))
				{
					opts.is_file = 1;
					opts.filename = av[opts.n_opts + j];
					g_cmd[i].f(buf, &opts);
					free(buf);
				}
				else
					g_cyph[i].f(av[opts.n_opts + j], &opts, av);
			}
			*/
		}
	return (0);
}

static int				check_format(int ac, char **av, t_options *opts)
{
	if (ac < 2)
	{
		ft_printf(USAGE);
		return (-1);
	}
	if (get_cypher(av[1], opts) == -1)
	{
		ft_printf("ft_ssl: Error: '%s' is an invalid command.\n", av[1]);
		return (-1);
	}
/*
	if (str && ac == 3)
	{
		ft_printf("option requires an argument -- s\n");
		return (-1);
	}
*/
	return (0);
}

int				main(int ac, char **av)
{
	int			i;
	char		*buf;
	t_options	opts;

	i = 2;
	ft_bzero(&opts, sizeof(t_options));
	while (av[i])
	{
		if (!parse_opts(av[i], &opts, i))
			return (0);
		opts.n_opts++;
		i++;
	}
	if (check_format(ac, av, &opts) < 0)
		return (-1);
	ft_bzero(&buf, sizeof(char*));
	if (!opts.pass && (ac - opts.n_opts) == 2)
	{
		buf = get_stdin();
		opts.is_stdin = 1;
	}
	parse_args(av, buf, opts, -1);
	return (0);
}
