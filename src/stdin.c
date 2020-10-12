/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   stdin.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/11 16:33:43 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/12 12:06:34 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

char	*update_buffer(char *dest, char *src, size_t current_size, size_t size)
{
	char *tmp;

	if (dest == NULL)
	{
		dest = malloc(size + 1);
		if (!dest)
			return (NULL);
		ft_memcpy(dest, src, size);
		return (dest);
	}
	tmp = dest;
	dest = malloc(current_size + size + 1);
	ft_memcpy(dest, tmp, current_size);
	ft_memcpy(dest + current_size, src, size);
	free(tmp);
	return (dest);
}

char	*get_file(char *file)
{
	char	*ret;
	char	buff[4096];
	size_t	total_size;
	int		rd;
	int		fd;

	total_size = 0;
	if ((fd = open(file, O_RDONLY)) < 0)
		return (NULL);
	ret = NULL;
	while ((rd = read(fd, buff, 4096)) > 0)
	{
		ret = update_buffer(ret, buff, total_size, rd);
		total_size += rd;
	}
	close(fd);
	if (rd < 0)
		return (NULL);
	if (ret)
		ret[total_size] = 0;
	return (ret);
}

char	*get_stdin(void)
{
	char	*ret;
	char	buff[4096];
	size_t	total_size;
	int		rd;

	total_size = 0;
	ret = NULL;
	while ((rd = read(STDIN_FILENO, buff, 4096)) > 0)
	{
		ret = update_buffer(ret, buff, total_size, rd);
		total_size += rd;
		if (ret[total_size - 1] == '\n')
			break ;
	}
	if (rd < 0)
		return (NULL);
	if (ret)
		ret[total_size] = 0;
	return (ret);
}
