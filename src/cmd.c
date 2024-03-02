// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

static void shell_whoami(word_t *params)
{
	int count = 0;

	word_t *p = params;

	while (p != NULL) {
		count++;
		p = p->next_word;
	}

	count += 2;
	char *args[count];

	args[0] = "whoami";

	int i = 1;

	for (p = params; p != NULL; p = p->next_word, i++)
		args[i] = p->string;
	args[count - 1] = NULL;

	execvp("whoami", args);

	perror("execvp failed");
	exit(EXIT_FAILURE);
}

static void shell_uname(word_t *params)
{
	int count = 0;

	word_t *p = params;

	while (p != NULL) {
		count++;
		p = p->next_word;
	}

	count += 2;
	char *args[count];

	args[0] = "uname";

	int i = 1;

	for (p = params; p != NULL; p = p->next_word, i++)
		args[i] = p->string;
	args[count - 1] = NULL;

	execvp("uname", args);

	perror("execvp failed");
	exit(EXIT_FAILURE);
}

static void shell_pwd(void)
{
	char cwd[1024];

	if (getcwd(cwd, sizeof(cwd)) != NULL)
		printf("%s\n", cwd);
	else
		perror("pwd failed");
}

static void shell_echo(word_t *params)
{
	word_t *p = params;

	while (p != NULL) {
		char *word = get_word(p);

		if (word) {
			printf("%s", word);
			free(word);
		}

		if (p->next_word != NULL)
			printf(" ");

		p = p->next_word;
	}

	printf("\n");
}

static void shell_cat(simple_command_t *cmd)
{
	int argc = 0;

	for (word_t *p = cmd->params; p != NULL; p = p->next_word)
		argc++;

	char *argv[argc + 2];

	argv[0] = "cat";
	word_t *p = cmd->params;

	for (int i = 1; i <= argc; i++) {
		argv[i] = p->string;
		p = p->next_word;
	}
	argv[argc + 1] = NULL;

	execvp(argv[0], argv);

	perror("execvp failed");
	exit(EXIT_FAILURE);
}

static int shell_exit(void)
{
	/* TODO: Execute exit/quit. */

	exit(SHELL_EXIT); /* TODO: Replace with actual exit code. */
}

static int shell_exec(simple_command_t *s)
{
	// Convert params linked list to argument array for execvp
	int argc = 0;

	for (word_t *p = s->params; p != NULL; p = p->next_word)
		argc++;

	char *argv[argc + 2]; // +1 for the command, +1 for NULL

	argv[0] = s->verb->string; // The command itself
	word_t *p = s->params; // Reset p to the start of the params list

	for (int i = 1; i <= argc; i++) {
		argv[i] = p->string;
		p = p->next_word;
	}
	argv[argc + 1] = NULL;

	// Execute the script or binary
	execvp(argv[0], argv);

	// If execvp returns, there was an error
	fprintf(stderr, "Execution failed for '%s'\n", argv[0]);
	return -1;
}

static void shell_cp(simple_command_t *cmd)
{
	if (cmd->params == NULL || cmd->params->next_word == NULL) {
		fprintf(stderr, "cp: missing file operand\n");
		return;
	}

	const char *src = cmd->params->string;      // Source file

	const char *dest = cmd->params->next_word->string; // Destination file

	int src_fd = open(src, O_RDONLY);

	if (src_fd < 0) {
		perror("cp: open src");
		return;
	}

	int dest_fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0644);

	if (dest_fd < 0) {
		perror("cp: open dest");
		close(src_fd);
		return;
	}

	char buffer[4096]; // Buffer for file contents

	ssize_t bytes_read;

	while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0) {
		if (write(dest_fd, buffer, bytes_read) != bytes_read) {
			perror("cp: write");
			break;
		}
	}

	if (bytes_read < 0)
		perror("cp: read");

	close(src_fd);
	close(dest_fd);
}

static void shell_rm(word_t *params)
{
	if (params == NULL) {
		fprintf(stderr, "rm: missing operand\n");
		exit(EXIT_FAILURE);
	}

	int count = 0;

	for (word_t *p = params; p != NULL; p = p->next_word)
		count++;

	char *args[count + 2];  // +2 for command and NULL

	args[0] = "rm";

	int i = 1;

	for (word_t *p = params; p != NULL; p = p->next_word, i++)
		args[i] = p->string;
	args[count + 1] = NULL;

	execvp(args[0], args);

	perror("execvp failed for rm");
	exit(EXIT_FAILURE);
}

static void shell_mkdir(word_t *params)
{
	if (params == NULL) {
		fprintf(stderr, "mkdir: missing operand\n");
		exit(EXIT_FAILURE);
	}

	int count = 0;

	for (word_t *p = params; p != NULL; p = p->next_word)
		count++;

	char *args[count + 2];  // +2 for command and NULL

	args[0] = "mkdir";

	int i = 1;

	for (word_t *p = params; p != NULL; p = p->next_word, i++)
		args[i] = p->string;
	args[count + 1] = NULL;

	execvp(args[0], args);

	perror("execvp failed for mkdir");
	exit(EXIT_FAILURE);
}

static void shell_ls(word_t *params)
{
	int count = 0;

	for (word_t *p = params; p != NULL; p = p->next_word)
		count++;

	char *args[count + 2];  // +2 for command and NULL

	args[0] = "ls";

	int i = 1;

	for (word_t *p = params; p != NULL; p = p->next_word, i++)
		args[i] = p->string;
	args[count + 1] = NULL;

	execvp(args[0], args);

	perror("execvp failed for ls");
	exit(EXIT_FAILURE);
}

static void shell_tr(word_t *params)
{
	if (params == NULL) {
		fprintf(stderr, "tr: missing operand\n");
		exit(EXIT_FAILURE);
	}

	int count = 0;

	for (word_t *p = params; p != NULL; p = p->next_word)
		count++;

	char *args[count + 2];  // +2 for command and NULL

	args[0] = "tr";

	int i = 1;

	for (word_t *p = params; p != NULL; p = p->next_word, i++)
		args[i] = p->string;
	args[count + 1] = NULL;

	execvp(args[0], args);

	perror("execvp failed for tr");
	exit(EXIT_FAILURE);
}

static void shell_cut(word_t *params)
{
	if (params == NULL) {
		fprintf(stderr, "cut: missing operand\n");
		exit(EXIT_FAILURE);
	}

	int count = 0;

	for (word_t *p = params; p != NULL; p = p->next_word)
		count++;

	char *args[count + 2];  // +2 for command and NULL

	args[0] = "cut";

	int i = 1;

	for (word_t *p = params; p != NULL; p = p->next_word, i++)
		args[i] = p->string;
	args[count + 1] = NULL;

	execvp(args[0], args);

	perror("execvp failed for cut");
	exit(EXIT_FAILURE);
}

static void shell_sort(word_t *params)
{
	int count = 0;

	for (word_t *p = params; p != NULL; p = p->next_word)
		count++;

	char *args[count + 2];  // +2 for command and NULL

	args[0] = "sort";

	int i = 1;

	for (word_t *p = params; p != NULL; p = p->next_word, i++)
		args[i] = p->string;
	args[count + 1] = NULL;

	execvp(args[0], args);

	perror("execvp failed for sort");
	exit(EXIT_FAILURE);
}

static void shell_uniq(word_t *params)
{
	int count = 0;

	for (word_t *p = params; p != NULL; p = p->next_word)
		count++;

	char *args[count + 2];  // +2 for command and NULL

	args[0] = "uniq";

	int i = 1;

	for (word_t *p = params; p != NULL; p = p->next_word, i++)
		args[i] = p->string;
	args[count + 1] = NULL;

	execvp(args[0], args);

	perror("execvp failed for uniq");
	exit(EXIT_FAILURE);
}

static void shell_wc(word_t *params)
{
	if (params == NULL) {
		fprintf(stderr, "wc: missing operand\n");
		exit(EXIT_FAILURE);
	}

	int count = 0;

	for (word_t *p = params; p != NULL; p = p->next_word)
		count++;

	char *args[count + 2];  // +2 for command and NULL

	args[0] = "wc";

	int i = 1;

	for (word_t *p = params; p != NULL; p = p->next_word, i++)
		args[i] = p->string;
	args[count + 1] = NULL;

	execvp(args[0], args);

	perror("execvp failed for wc");
	exit(EXIT_FAILURE);
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	int in_fd = -1, out_fd = -1, err_fd = -1; // File descriptors for redirection

	// Redirect input if needed
	if (s->in != NULL) {
		in_fd = open(s->in->string, O_RDONLY);
		if (in_fd < 0) {
			perror("Failed to open input file");
			return -1;
		}
	}

	// Redirect error if needed
	if (s->err != NULL && (s->io_flags & IO_ERR_APPEND)) {
		err_fd = open(s->err->string, O_WRONLY | O_CREAT | O_APPEND, 0644);
		if (err_fd < 0) {
			perror("Failed to open error file for appending");
			if (in_fd != -1)
				close(in_fd);
			if (out_fd != -1)
				close(out_fd);
			return -1;
		}
	} else if (s->err != NULL) {
		err_fd = open(s->err->string, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (err_fd < 0) {
			perror("Failed to open error file");
			if (in_fd != -1)
				close(in_fd);
			if (out_fd != -1)
				close(out_fd);
			return -1;
		}
	}

	if (s->out != NULL) {
		// Choose the correct flags based on io_flags
		int flags = O_WRONLY | O_CREAT;

		if (s->io_flags & IO_OUT_APPEND) {
			// Append instead of truncate
			flags |= O_APPEND;
		} else {
			// Truncate the file
			flags |= O_TRUNC;
		}

		out_fd = open(get_word(s->out), flags, 0644);
		if (out_fd < 0) {
			perror("Failed to open output file");
			if (in_fd != -1)
				close(in_fd);
			return -1;
		}
	}

	if (s->out != NULL && s->err != NULL && strcmp(s->out->string, s->err->string) == 0) {
		// This condition checks if both output and error redirection are to the same file
		int flags = O_WRONLY | O_CREAT;

		if (s->io_flags & IO_OUT_APPEND) {
			// Append to the file if the append flag is set
			flags |= O_APPEND;
		} else {
			// Otherwise, truncate the file
			flags |= O_TRUNC;
		}

		int common_fd = open(s->out->string, flags, 0644);

		if (common_fd < 0) {
			perror("Failed to open common output/error file");
			return -1;
		}

		out_fd = err_fd = common_fd; // Use the same file descriptor for both
	}

	if (strcmp(s->verb->string, "exit") == 0 || strcmp(s->verb->string, "quit") == 0) {
		shell_exit();
	} else if (strcmp(s->verb->string, "cd") == 0) {
		if (s->params == NULL || s->params->string == NULL) {
			// No argument to cd, go to the home directory
			const char *home = getenv("HOME");

			if (home == NULL) {
				fprintf(stderr, "cd: HOME not set\n");
				return -1;
			}
			if (chdir(home) != 0) {
				perror("cd");
				return -1;
			}
		} else {
			if (chdir(s->params->string) != 0) {
				perror("cd");
				return -1;
			}
		}

	} else if (strcmp(s->verb->string, "true") == 0) {
		return 0;
	} else if (strcmp(s->verb->string, "false") == 0) {
		return 1;
	}

	word_t *current = s->verb;

	if (current && current->next_part && strcmp(current->next_part->string, "=") == 0) {
		// We have an assignment statement
		const char *var_name = current->string;
		const char *var_value = get_word(current->next_part->next_part);

		if (var_value)
			setenv(var_name, var_value, 1); // Set the environment variable
	}

	pid_t pid = fork();

	if (pid == -1) {
		perror("fork failed");
		return -1;
	} else if (pid == 0) {
		// Child process: set up redirection
		if (in_fd != -1) {
			dup2(in_fd, STDIN_FILENO);
			close(in_fd);
		}
		if (out_fd != -1) {
			dup2(out_fd, STDOUT_FILENO);
			if (out_fd != err_fd)
				close(out_fd);
		}
		if (err_fd != -1) {
			dup2(err_fd, STDERR_FILENO);
			if (err_fd != out_fd)
				close(err_fd);
		}

		if (strcmp(s->verb->string, "echo") == 0) {
			shell_echo(s->params);
		} else if (strcmp(s->verb->string, "whoami") == 0) {
			shell_whoami(s->params);
		} else if (strcmp(s->verb->string, "uname") == 0) {
			shell_uname(s->params);
		} else if (strcmp(s->verb->string, "pwd") == 0) {
			shell_pwd();
		} else if (strcmp(s->verb->string, "cat") == 0) {
			shell_cat(s);
		} else if (s->verb->string[0] == '.' && s->verb->string[1] == '/') {
			int exec_status = shell_exec(s);

			exit(exec_status == -1 ? EXIT_FAILURE : EXIT_SUCCESS);
		} else if (strcmp(s->verb->string, "cp") == 0) {
			shell_cp(s);
		} else if (strcmp(s->verb->string, "rm") == 0) {
			shell_rm(s->params);
		} else if (strcmp(s->verb->string, "mkdir") == 0) {
			shell_mkdir(s->params);
		} else if (strcmp(s->verb->string, "ls") == 0) {
			shell_ls(s->params);
		} else if (strcmp(s->verb->string, "tr") == 0) {
			shell_tr(s->params);
		} else if (strcmp(s->verb->string, "cut") == 0) {
			shell_cut(s->params);
		} else if (strcmp(s->verb->string, "sort") == 0) {
			shell_sort(s->params);
		} else if (strcmp(s->verb->string, "uniq") == 0) {
			shell_uniq(s->params);
		} else if (strcmp(s->verb->string, "wc") == 0) {
			shell_wc(s->params);
		} else if (strcmp(s->verb->string, "cd") != 0 &&
		!(current && current->next_part && strcmp(current->next_part->string, "=") == 0)) {
			int exec_status = shell_exec(s);

			exit(exec_status == -1 ? EXIT_FAILURE : EXIT_SUCCESS);
		}

		// Exit the child process
		exit(EXIT_SUCCESS);
	} else {
		// Parent process: wait for child to finish
		int status;

		waitpid(pid, &status, 0);

		// Close file descriptors in the parent process if they were opened
		if (in_fd != -1)
			close(in_fd);
		if (out_fd != -1)
			close(out_fd);
		if (err_fd != -1)
			close(err_fd);

		if (WIFEXITED(status))
			return WEXITSTATUS(status);
		else
			return 0;
	}

	/* TODO: If variable assignment, execute the assignment and return
	 * the exit status.
	 */

	/* TODO: If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */

	return 0; /* TODO: Replace with actual exit status. */
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO: Execute cmd1 and cmd2 simultaneously. */

	return true; /* TODO: Replace with actual exit status. */
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	int pipefd[2];

	if (pipe(pipefd) == -1) {
		perror("pipe");
		return false;
	}

	pid_t pid1 = fork();

	if (pid1 == -1) {
		perror("fork");
		return false;
	}

	int exit_code1 = 0, exit_code2 = 0;

	if (pid1 == 0) {
		// Child process for the left side of the pipe (cmd1)
		close(pipefd[READ]); // Close the unused read end
		dup2(pipefd[WRITE], STDOUT_FILENO); // Redirect stdout to the pipe's write end
		close(pipefd[WRITE]); // Close the write end after dup2

		// Execute the command
		_exit(parse_command(cmd1, level + 1, father));
	}

	// Parent process
	pid_t pid2 = fork();

	if (pid2 == -1) {
		perror("fork");
		return false;
	}

	if (pid2 == 0) {
		// Child process for the right side of the pipe (cmd2)
		close(pipefd[WRITE]); // Close the unused write end
		dup2(pipefd[READ], STDIN_FILENO); // Redirect stdin to the pipe's read end
		close(pipefd[READ]); // Close the read end after dup2

		// Execute the command
		_exit(parse_command(cmd2, level + 1, father));
	}

	// Parent process
	close(pipefd[READ]); // Close the read end
	close(pipefd[WRITE]); // Close the write end

	int exit_status;

	waitpid(pid1, NULL, 0);
	waitpid(pid2, &exit_status, 0);
	return WIFEXITED(exit_status) && (WEXITSTATUS(exit_status) == 0);
}



/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* TODO: sanity checks */
	if (c == NULL)
		return -1;

	if (c->op == OP_NONE) {
		/* TODO: Execute a simple command. */
		return parse_simple(c->scmd, level, father);
	}

	int exit_code1 = 0, exit_code2 = 0;

	switch (c->op) {
	case OP_SEQUENTIAL:
		parse_command(c->cmd1, level + 1, father);
		parse_command(c->cmd2, level + 1, father);
		break;

	case OP_PARALLEL:
some_label:
		;
		pid_t child_pid1 = fork();

		if (child_pid1 == 0) {
			exit(parse_command(c->cmd1, level + 1, c));
		} else {
			pid_t child_pid2 = fork();

			if (child_pid2 == 0) {
				exit(parse_command(c->cmd2, level + 1, c));
			} else {
				int status1, status2;

				waitpid(child_pid1, &status1, 0);
				waitpid(child_pid2, &status2, 0);
			}
		}

		break;

	case OP_CONDITIONAL_NZERO:
		exit_code1 = parse_command(c->cmd1, level + 1, father);
		// Execute the second command only if the first one fails.
		if (exit_code1 != 0)
			exit_code2 = parse_command(c->cmd2, level + 1, father);
		break;

	case OP_CONDITIONAL_ZERO:
		// Execute the first command.
		exit_code1 = parse_command(c->cmd1, level + 1, father);

		// Execute the second command only if the first one succeeds.
		if (exit_code1 == 0)
			exit_code2 = parse_command(c->cmd2, level + 1, father);
		break;

	case OP_PIPE:
		exit_code2 = !run_on_pipe(c->cmd1, c->cmd2, level, father);
		break;

	default:
		return SHELL_EXIT;
	}

	return exit_code2; /* TODO: Replace with actual exit code of command. */
}
