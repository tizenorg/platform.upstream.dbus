/*
 * kdbus_common.c
 *
 *  Created on: Sep 13, 2013
 *      Author: r.pajak
 *
 *  Kdbus internal util functions used by daemon and libdbus
 */

#include "kdbus.h"
#include "kdbus-common.h"
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <dbus/dbus-internals.h>
#include <dbus/dbus-shared.h>

static struct kdbus_policy *make_policy_name(const char *name)
{
	struct kdbus_policy *p;
	__u64 size;

	size = offsetof(struct kdbus_policy, name) + strlen(name) + 1;
	p = malloc(size);
	if (!p)
		return NULL;
	memset(p, 0, size);
	p->size = size;
	p->type = KDBUS_POLICY_NAME;
	strcpy(p->name, name);

	return p;
}

static struct kdbus_policy *make_policy_access(__u64 type, __u64 bits, __u64 id)
{
	struct kdbus_policy *p;
	__u64 size = sizeof(*p);

	p = malloc(size);
	if (!p)
		return NULL;

	memset(p, 0, size);
	p->size = size;
	p->type = KDBUS_POLICY_ACCESS;
	p->access.type = type;
	p->access.bits = bits;
	p->access.id = id;

	return p;
}

static void append_policy(struct kdbus_cmd_policy *cmd_policy, struct kdbus_policy *policy, __u64 max_size)
{
	struct kdbus_policy *dst = (struct kdbus_policy *) ((char *) cmd_policy + cmd_policy->size);

	if (cmd_policy->size + policy->size > max_size)
		return;

	memcpy(dst, policy, policy->size);
	cmd_policy->size += KDBUS_ALIGN8(policy->size);
	free(policy);
}

/**
 * Registers kdbus policy for given connection.
 *
 * Policy sets rights of the name (unique or well known) on the bus. Without policy it is
 * not possible to send or receive messages. It must be set separately for unique id and
 * well known name of the connection. It is set after registering on the bus, but before
 * requesting for name. The policy is valid for the given name, not for the connection.
 *
 * Name of the policy equals name on the bus.
 *
 * @param name name of the policy = name of the connection
 * @param connection the connection
 * @param error place to store errors
 *
 * @returns #TRUE on success
 */
dbus_bool_t register_kdbus_policy(const char* name, int fd)
{
	struct kdbus_cmd_policy *cmd_policy;
	struct kdbus_policy *policy;
	int size = 0xffff;

	cmd_policy = alloca(size);
	memset(cmd_policy, 0, size);

	policy = (struct kdbus_policy *) cmd_policy->policies;
	cmd_policy->size = offsetof(struct kdbus_cmd_policy, policies);

	policy = make_policy_name(name);
	append_policy(cmd_policy, policy, size);

	policy = make_policy_access(KDBUS_POLICY_ACCESS_USER, KDBUS_POLICY_OWN, getuid());
	append_policy(cmd_policy, policy, size);

	policy = make_policy_access(KDBUS_POLICY_ACCESS_WORLD, KDBUS_POLICY_RECV, 0);
	append_policy(cmd_policy, policy, size);

	policy = make_policy_access(KDBUS_POLICY_ACCESS_WORLD, KDBUS_POLICY_SEND, 0);
	append_policy(cmd_policy, policy, size);

	if (ioctl(fd, KDBUS_CMD_EP_POLICY_SET, cmd_policy) < 0)
	{
		_dbus_verbose ("Error setting policy: %m, %d\n", errno);
		return FALSE;
	}

	_dbus_verbose("Policy %s set correctly\n", name);
	return TRUE;
}

dbus_bool_t list_kdbus_names(int fd, char ***listp, int *array_len)
{
	struct kdbus_cmd_names* pCmd;
	__u64 cmd_size;
	dbus_bool_t ret_val = FALSE;
	char** list;
	int list_len = 0;
	int i = 0;
	int j;

	cmd_size = sizeof(struct kdbus_cmd_names) + KDBUS_ITEM_SIZE(1);
	pCmd = malloc(cmd_size);
	if(pCmd == NULL)
		goto out;
	pCmd->size = cmd_size;

again:
	cmd_size = 0;
	if(ioctl(fd, KDBUS_CMD_NAME_LIST, pCmd))
	{
		if(errno == EINTR)
			goto again;
		if(errno == ENOBUFS)			//buffer to small to put all names into it
			cmd_size = pCmd->size;		//here kernel tells how much memory it needs
		else
		{
			_dbus_verbose("kdbus error asking for name list: err %d (%m)\n",errno);
			goto out;
		}
	}
	if(cmd_size)  //kernel needs more memory
	{
		pCmd = realloc(pCmd, cmd_size);  //prepare memory
		if(pCmd == NULL)
			return FALSE;
		goto again;						//and try again
	}
	else
	{
		struct kdbus_cmd_name* pCmd_name;

		for (pCmd_name = pCmd->names; (uint8_t *)(pCmd_name) < (uint8_t *)(pCmd) + pCmd->size; pCmd_name = KDBUS_PART_NEXT(pCmd_name))
			list_len++;

		list = malloc(sizeof(char*) * (list_len + 1));
		if(list == NULL)
			goto out;

		for (pCmd_name = pCmd->names; (uint8_t *)(pCmd_name) < (uint8_t *)(pCmd) + pCmd->size; pCmd_name = KDBUS_PART_NEXT(pCmd_name))
		{
			list[i] = strdup(pCmd_name->name);
			if(list[i] == NULL)
			{
				for(j=0; j<i; j++)
					free(list[j]);
				free(list);
				goto out;
			}
			_dbus_verbose ("Name %d: %s\n", i, list[i]);
			++i;
		}
		list[i] = NULL;
	}

	*array_len = list_len;
	*listp = list;
	ret_val = TRUE;

out:
	if(pCmd)
		free(pCmd);
	return ret_val;
}

/**
 * kdbus version of dbus_bus_request_name.
 *
 * Asks the bus to assign the given name to this connection.
 *
 * Use same flags as original dbus version with one exception below.
 * Result flag #DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER is currently
 * never returned by kdbus, instead DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER
 * is returned by kdbus.
 *
 * @param connection the connection
 * @param name the name to request
 * @param flags flags
 * @param error location to store the error
 * @returns a result code, -1 if error is set
 */
int request_kdbus_name(int fd, const char *name, const __u64 flags, __u64 id)
{
	struct kdbus_cmd_name *cmd_name;

	__u64 size = sizeof(*cmd_name) + strlen(name) + 1;
	__u64 flags_kdbus = 0;

	cmd_name = alloca(size);

//	memset(cmd_name, 0, size);
	strcpy(cmd_name->name, name);
	cmd_name->size = size;

	if(flags & DBUS_NAME_FLAG_ALLOW_REPLACEMENT)
		flags_kdbus |= KDBUS_NAME_ALLOW_REPLACEMENT;
	if(!(flags & DBUS_NAME_FLAG_DO_NOT_QUEUE))
		flags_kdbus |= KDBUS_NAME_QUEUE;
	if(flags & DBUS_NAME_FLAG_REPLACE_EXISTING)
		flags_kdbus |= KDBUS_NAME_REPLACE_EXISTING;
	if(flags & KDBUS_NAME_STARTER)
	    flags_kdbus |= KDBUS_NAME_STARTER;

	cmd_name->flags = flags_kdbus;
	cmd_name->id = id;
//	cmd_name->conn_flags = 0;

	_dbus_verbose("Request name - flags sent: 0x%llx       !!!!!!!!!\n", cmd_name->flags);

	if (ioctl(fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name))
	{
		_dbus_verbose ("error acquiring name '%s': %m, %d\n", name, errno);
		if(errno == EEXIST)
			return DBUS_REQUEST_NAME_REPLY_EXISTS;
		return -errno;
	}

	_dbus_verbose("Request name - received flag: 0x%llx       !!!!!!!!!\n", cmd_name->flags);

	if(cmd_name->flags & KDBUS_NAME_IN_QUEUE)
		return DBUS_REQUEST_NAME_REPLY_IN_QUEUE;
	else
		return DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER;
	/*todo now 1 code is never returned -  DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER
	 * because kdbus never returns it now
	 */
}

int release_kdbus_name(int fd, const char *name, __u64 id)
{
	struct kdbus_cmd_name *cmd_name;

	__u64 size = sizeof(*cmd_name) + strlen(name) + 1;

	cmd_name = alloca(size);
	cmd_name->id = id;
	strcpy(cmd_name->name, name);
	cmd_name->size = size;

	if (ioctl(fd, KDBUS_CMD_NAME_RELEASE, cmd_name))
	{
		if(errno == ESRCH)
			return DBUS_RELEASE_NAME_REPLY_NON_EXISTENT;
		else if (errno == EPERM)
			return DBUS_RELEASE_NAME_REPLY_NOT_OWNER;
		_dbus_verbose ("error releasing name '%s' for id:%llu. Error: %m, %d\n", name, (unsigned long long)id, errno);
		return -errno;
	}

	_dbus_verbose("Name '%s' released\n", name);

	return DBUS_RELEASE_NAME_REPLY_RELEASED;
}
