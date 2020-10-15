/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/11 18:00:41 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/15 12:44:54 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"
/*
t_cypher_cmd	g_cyph[] =
{
	{"base64", handle_64},
	{"des", handle_des},
	{"des-ecb", handle_ecb},
	{"des-cbc", handle_cbc},
	{0}
}
*/
t_digest_cmd	g_cmd[] =
{
	{"md5", handle_md5},
	{"sha256", handle_256},
	{"sha224", handle_224},
	{0}
};

int				get_cmd(char *cmd)
{
	int i;

	i = 0;
	while (g_cmd[i].cmd)
	{
		if (!(ft_strncmp(g_cmd[i].cmd, cmd, ft_strlen(g_cmd[i].cmd))))
			return (i);
		i++;
	}
	return (-1);
}

int				parse_args(char **av, char *buf, t_arg_opts opts, int i)
{
	int	j;

	while (g_cmd[++i].cmd)
		if (!(ft_strncmp(g_cmd[i].cmd, av[1], ft_strlen(g_cmd[i].cmd))))
		{
			j = 1;
			if (opts.is_stdin)
				g_cmd[i].f(buf, &opts);
			while (av[opts.n_opts + ++j])
			{
				opts.is_stdin = 0;
				if (av[opts.n_opts + j][0] == '-')
					return (wrong_format(g_cmd[i].cmd, &av[opts.n_opts + j]));
				if ((buf = get_file(av[opts.n_opts + j])))
				{
					opts.is_file = 1;
					opts.filename = av[opts.n_opts + j];
					g_cmd[i].f(buf, &opts);
					free(buf);
				}
				else
					g_cmd[i].f(av[opts.n_opts + j], &opts);
			}
		}
	return (0);
}

int				check_format(int ac, char **av, int str)
{
	if (ac < 2)
	{
		ft_printf(USAGE);
		return (-1);
	}
	if (get_cmd(av[1]) == -1)
	{
		ft_printf("ft_ssl: Error: '%s' is an invalid command.\n");
		return (-1);
	}
	if (str && ac == 3)
	{
		ft_printf("option requires an argument -- s\n");
		return (-1);
	}
	return (0);
}

int				main(int ac, char **av)
{
	int			i;
	char		*buf;
	t_arg_opts	opts;

	i = 2;
	if (check_format(ac, av, 0) == -1)
		return (-1);
	ft_bzero(&opts, sizeof(t_arg_opts));
	while (av[i] && av[i][0] == '-')
	{
		if (!parse_opts(av[i], &opts))
			return (0);
		opts.n_opts++;
		i++;
	}
	if (check_format(ac, av, opts.str) == -1)
		return (-1);
	ft_bzero(&buf, sizeof(char*));
	if (opts.echo == 1 || (ac - opts.n_opts) == 2)
	{
	//	if ((buf = get_stdin()) != NULL)
		buf = get_stdin();
		opts.is_stdin = 1;
	}
	parse_args(av, buf, opts, -1);
	if (buf != NULL)
		free(buf);
	return (0);
}
