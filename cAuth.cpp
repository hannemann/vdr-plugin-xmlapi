#include "cAuth.h"
#include "globals.h"

cAuth::cAuth(struct MHD_Connection *connection, cDaemonParameter *daemonParameter, const char *url)
	: connection(connection),
	  daemonParameter(daemonParameter),
	  url(url),
	  config(daemonParameter->GetPluginConfig()) {

	this->session = NULL;
};

cAuth::~cAuth() {

	this->connection = NULL;
	this->session = NULL;
};

const char *cAuth::getCookie() {

	const char *cookie = NULL;
	const char *cookieFromUrl = NULL;
	string urlStr = this->url;

	cookie = MHD_lookup_connection_value (this->connection,
			MHD_COOKIE_KIND,
			"xmlapi-sid");


	if (cookie == NULL && this->isHlsStreamUrl()) {
		vector<string> parts = split(urlStr.substr(0, urlStr.find_last_of(".")), '-');
		cookieFromUrl = parts[2].c_str();
		dsyslog("xmlapi: sid from url: %s", cookieFromUrl);

		return cookieFromUrl;
	}

	return cookie;
};

bool cAuth::isHlsStreamUrl() {

	return startswith(this->url, "/hls/");
};

bool cAuth::authSession() {

	bool hasSession = false;

	const char *cookie = this->getCookie();

	if (cookie != NULL) {

		dsyslog("xmlapi: found cookie id: %s", cookie);

		while (SessionControl->locked) {
			usleep(1000);
		}

		SessionControl->Mutex.Lock();
		string sessionid(cookie);
		cSession* session = SessionControl->GetSessionBySessionId(sessionid);
		dsyslog("xmlapi: found session width id: %s", cookie);

		if (session != NULL && !session->IsExpired()) {
			const cUser *sessionUser = SessionControl->GetUserBySessionId(sessionid);
			if(sessionUser != NULL) {
				this->user = this->config.GetUsers().GetUser(sessionUser->Name().c_str());
				dsyslog("xmlapi: found user %s session width id: %s", this->user.Name().c_str(), cookie);
				this->session = session;
				this->session->UpdateStart();
				hasSession = true;
				dsyslog("xmlapi: authSession() -> authenticated user %s", this->user.Name().c_str());
				dsyslog("xmlapi: session id: %s", sessionid.c_str());
				dsyslog("xmlapi: requested url: %s", this->url);
			}
		} else {

			dsyslog("xmlapi: cannot find session for id: %s", cookie);
		}
		SessionControl->Mutex.Unlock();
	}

	return hasSession;
};

bool cAuth::authBasic() {

	bool validUser = true;
	const char* createAction = "1200";
    long lifetime = atol(createAction);

    if(!this->config.GetUsers().empty()) {
        char *user = NULL;
        char *pass = NULL;
        user = MHD_basic_auth_get_username_password (this->connection, &pass);
		dsyslog("xmlapi: found user %s", user);
        validUser = user != NULL && this->config.GetUsers().MatchUser(user, pass);
        if (validUser) {
    		dsyslog("xmlapi: found user %s matches password", user);
        	this->user = this->config.GetUsers().GetUser(user);
        	cSession session = SessionControl->AddSession(this->user, lifetime);
        	this->session = SessionControl->GetSessionBySessionId(session.GetSessionId());
			dsyslog("xmlapi: !!!!!!!!!!!!!authBasic() -> authenticated user %s", this->user.Name().c_str());
			dsyslog("xmlapi: session id: %s", this->session->GetSessionId().c_str());
			dsyslog("xmlapi: requested url: %s", this->url);
        } else {
    		dsyslog("xmlapi: auth failed for user %s", user);
        }
        if (user != NULL) free (user);
        if (pass != NULL) free (pass);
    } else {
    	cSession session = SessionControl->AddSession(this->user, lifetime);
    	this->session = SessionControl->GetSessionBySessionId(session.GetSessionId());
		dsyslog("xmlapi: !!!!!!!!!!!!!authBasic() -> authenticated user %s", this->user.Name().c_str());
		dsyslog("xmlapi: session id: %s", this->session->GetSessionId().c_str());
		dsyslog("xmlapi: requested url: %s", this->url);
    }
    return validUser;
};

bool cAuth::authenticated() {

	return this->authSession() || this->authBasic();
};
