
#ifndef CAUTH_H
#define CAUTH_H

#include <string>
#include <microhttpd.h>
#include "cDaemonParameter.h"
#include "cPluginConfig.h"
#include "cSession.h"
#include "cUser.h"
#include <unistd.h>

using namespace std;

class cAuth {

public:
	cAuth(struct MHD_Connection *connection, cDaemonParameter *daemonParameter, const char *url);
	virtual ~cAuth();
	bool authenticated();

	cUser User() { return this->user; };
	cSession *Session() { return this->session; };

private:
	struct MHD_Connection *connection;
    cDaemonParameter *daemonParameter;
	const char *url;
    cPluginConfig config;
	cUser user;
	cSession *session;

	bool authBasic();
	bool authSession();
	const char *getCookie();
	bool isHlsStreamUrl();
};

#endif /* CAUTH_H */
