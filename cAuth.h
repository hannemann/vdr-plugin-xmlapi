
#ifndef CAUTH_H
#define CAUTH_H

#include <string>
#include <microhttpd.h>
#include "cPluginConfig.h"
#include "cSession.h"
#include "cUser.h"

using namespace std;

class cAuth {

public:
	cAuth(struct MHD_Connection *connection, cPluginConfig config);
	virtual ~cAuth();
	bool authenticated();

	cUser User() { return this->user; };
	cSession *Session() { return this->session; };

private:
	struct MHD_Connection *connection;
    cPluginConfig config;
	cUser user;
	cSession *session;

	bool authBasic();
	bool authSession();
};

#endif /* CAUTH_H */