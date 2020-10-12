/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/07 11:21:19 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/11 20:26:52 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_H
# define LIBFT_H
# include <stdlib.h>
# include <string.h>
# include <unistd.h>
# include <wchar.h>
# include <locale.h>

# define BUF_SIZE 1024
# define BASE 16
# define DECIMAL 10
# define HEXA 16
# define HEXA_UPPER 17
# define OCTAL 8
# define OCTAL_UPPER 9
# define BINARY 2

typedef struct		s_list
{
	void			*content;
	size_t			content_size;
	struct s_list	*next;
}					t_list;

void				*ft_memset(void *b, int c, size_t len);
void				ft_bzero(void *s, size_t n);
void				*ft_memcpy(void *dst, const void *src, int n);
void				*ft_memccpy(void *dst, const void *src, int c, size_t n);
void				*ft_memmove(void*dst, const void *src, size_t len);
void				*ft_memchr(const void *s, int c, size_t n);
int					ft_memcmp(const void *s1, const void *s2, size_t n);
void				*ft_malloc_check(int size);
int					ft_strlen(const char *s);
char				*ft_strdup(const char *s1);
char				*ft_strcpy(char *dst, const char *src);
char				*ft_strncpy(char *dst, const char *src, size_t len);
char				*ft_strcat(char *s1, const char *s2);
char				*ft_strncat(char *s1, const char *s2, size_t n);
size_t				ft_strlcat(char *dst, const char *src, size_t size);
char				*ft_strchr(const char *s, int c);
char				*ft_strrchr(const char *s, int c);
int					ft_strichr(const char *s, int c);
char				*ft_strchrr(char *src, int c);
char				*ft_strstr(const char *big, const char *little);
char				*ft_strnstr(const char *big, const char *little,
					size_t len);
int					ft_strcmp(const char *s1, const char *s2);
int					ft_strncmp(const char *s1, const char *s2, size_t n);
int					ft_arraylen(char **array);
char				**ft_arraydup(char **array);
int					ft_atoi(const char *str);
int					ft_isalpha(int c);
int					ft_isdigit(int c);
int					ft_isalnum(int c);
int					ft_isascii(int c);
int					ft_isprint(int c);
int					ft_toupper(int c);
int					ft_tolower(int c);
void				*ft_memalloc(size_t size);
void				ft_memdel(void **ap);
char				*ft_strnew(size_t size);
void				ft_strdel(char **as);
int					ft_strequ(char const *s1, const char *s2);
int					ft_strnequ(char const *s1, char const *s2, size_t n);
char				*ft_strsub(char const *s, unsigned int start, size_t len);
char				*ft_strjoin(char const *s1, char const *s2);
char				*ft_strjoin_free(char const *s1, char const *s2);
char				*ft_strtrim(char const *s);
void				ft_putchar(char c);
void				ft_putstr(char const *s);
void				ft_putendl(char const *s);
void				ft_putnbr(int n);
void				ft_putnbr_fd(int n, int fd);
void				ft_putchar_fd(char c, int fd);
void				ft_putstr_fd(char const *s, int fd);
void				ft_putendl_fd(char const *s, int fd);
char				*ft_strnew(size_t size);
void				ft_strclr(char *s);
void				ft_striter(char *s, void (*f)(char *));
void				ft_striteri(char *s, void (*f)(unsigned int i, char *));
char				*ft_strmap(char const *s, char (*f)(char));
char				*ft_strmapi(char const *s, char (*f)(unsigned int, char));
char				*ft_itoa(int n);
char				*ft_itoabase(int n, int base, char *s);
char				**ft_strsplit(char const *s, char c);
t_list				*ft_lstnew(void const *content, int content_size);
void				ft_lstdelone(t_list **aslt, void (*del)(void *, size_t));
void				ft_lstdel(t_list **alst, void (*del)(void *, size_t));
void				ft_lstadd(t_list **alst, t_list *neww);
void				ft_lstiter(t_list *lst, void (*f)(t_list *elem));
t_list				*ft_lstmap(t_list *lst, t_list *(*f)(t_list *elem));
int					ft_sqrt(int nb);
void				ft_foreach(int *tab, int length, void(*f)(int));
int					*ft_range(int main, int max);
int					ft_recursive_factorial(int n);
int					ft_iswhitespace(int c);
int					ft_wstrlen(wchar_t *str);
int					ft_wcharlen(wint_t c);
wchar_t				*ft_wstrcpy(wchar_t *dst, const wchar_t *src);
short int			ft_charcmp(const char *str, size_t i, char c);
void				*ft_realloc(void *ptr, int size, int len);
char				*ft_charjoin(char *s1, const char c);
int					ft_intlen(int n, int base);
void				double_free(char **av);
char				**ft_stradd(char **array, char *content, int count);
int					get_next_line(const int fd, char **line);
char				*ft_get_input(void);
int					ft_numlen(long long num, int base, size_t size);
int					ft_unumlen(unsigned long long num);
void				ft_putstrn(char *str, int n);
void				ft_unicode_putchar(int c);

#endif
