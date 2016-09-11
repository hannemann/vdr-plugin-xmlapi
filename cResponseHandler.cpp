#include "cResponseHandler.h"
#include "globals.h"

cResponseHandler::cResponseHandler(struct MHD_Connection *connection, cSession *session, cDaemonParameter *daemonParameter)
	: connection(connection), session(session), daemonParameter(daemonParameter), config(daemonParameter->GetPluginConfig())
{
	this->user = NULL;
	if (this->session != NULL) {
		this->user = SessionControl->GetUserBySessionId(this->session->GetSessionId());
	}
	this->response = NULL;

	this->initConInfo();
};

cResponseHandler::~cResponseHandler() {

	this->session = NULL;
	this->user = NULL;
	this->destroyResponse();
	this->connection = NULL;
	this->daemonParameter = NULL;
};

cResponseHandler *cResponseHandler::setSession(cSession *session) {
	this->session = session;
	return this;
}

cResponseHandler *cResponseHandler::setUser(cUser *user) {
	this->user = user;
	return this;
}

cSession *cResponseHandler::getSession() {
	return this->session;
}

const cUser *cResponseHandler::getUser() {
	return this->user;
}

cResponseHandler *cResponseHandler::create(size_t size, void *buffer, enum MHD_ResponseMemoryMode mode) {

	this->response = MHD_create_response_from_buffer(size, buffer, mode);
	if (this->session != NULL) {
		this->header(MHD_HTTP_HEADER_SET_COOKIE, this->session->Cookie().c_str());
	}
	return this;
}

cResponseHandler *cResponseHandler::create(size_t size, int fd) {

	this->response = MHD_create_response_from_fd(size, fd);
	if (this->session != NULL) {
		this->header(MHD_HTTP_HEADER_SET_COOKIE, this->session->Cookie().c_str());
	}
	return this;
}

cResponseHandler *cResponseHandler::header(const char *header, const char *content) {

	MHD_add_response_header (this->response, header, content);
	return this;
};

cResponseHandler *cResponseHandler::cors() {

	this->cors(this->response);

	return this;
};

cResponseHandler *cResponseHandler::cors(MHD_Response *response) {

	MHD_add_response_header (response, "Access-Control-Allow-Origin", this->conInfo["Origin"].c_str());
	MHD_add_response_header (response, "Access-Control-Allow-Headers", "Authorization");
	MHD_add_response_header (response, "Access-Control-Allow-Credentials", "true");

	return this;
};

int cResponseHandler::flush(int status) {

    int ret = MHD_queue_response(this->connection, status, this->response);
    this->destroyResponse();
    return ret;
};

void cResponseHandler::destroyResponse() {
	if (this->response) {
		MHD_destroy_response (this->response);
		this->response = NULL;
	}
};

void cResponseHandler::initConInfo() {

    const MHD_ConnectionInfo *connectionInfo = MHD_get_connection_info (this->connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if (connectionInfo->client_addr->sa_family == AF_INET)
    {
        struct sockaddr_in *sin = (struct sockaddr_in *) connectionInfo->client_addr;
        char *ip = inet_ntoa(sin->sin_addr);
        if(ip != NULL)
        {
            this->conInfo.insert(pair<string,string>("ClientIP", string(ip)));
        }
    }
    const char *useragent = MHD_lookup_connection_value(this->connection, MHD_HEADER_KIND, "User-Agent");
    if(useragent != NULL)
    {
        this->conInfo.insert(pair<string,string>("User-Agent",string(useragent)));
    }
    const char *host = MHD_lookup_connection_value(this->connection, MHD_HEADER_KIND, "Host");
    if(host != NULL)
    {
        this->conInfo.insert(pair<string,string>("Host", string(host)));
    }
    const char *origin = NULL;
	string corsConfig = this->config.GetCorsOrigin();

	if ("auto" == corsConfig) {
		origin = MHD_lookup_connection_value(this->connection, MHD_HEADER_KIND, "Origin");
	} else {
		origin = corsConfig.c_str();
	}
    if(origin != NULL)
    {
        this->conInfo.insert(pair<string,string>("Origin", string(origin)));
    }
};

int cResponseHandler::handle404Error() {

    const char *page = "<html>\n"
                       "  <head>\n"
                       "    <title>404 Not Found</title>\n"
                       "  </head>\n"
                       "  <body>\n"
                       "    <h1>Not Found</h1>\n"
                       "    <p>The requested URL was not found on this server.</p>\n"
                       "  </body>\n"
                       "</html>\n";
    return this->create(strlen (page), (void *) page, MHD_RESPMEM_PERSISTENT)
		->header("Content-Type", "text/html")
		->cors()
		->flush(MHD_HTTP_NOT_FOUND);
}

int cResponseHandler::handle403Error() {

    const char *page = "<html>\n"
                       "  <head>\n"
                       "    <title>403 permission denied</title>\n"
                       "  </head>\n"
                       "  <body>\n"
                       "    <h1>Permission denied</h1>\n"
                       "    <p>You don't have the permission to access this site.</p>\n"
                       "  </body>\n"
                       "</html>\n";
    return this->create(strlen (page), (void *) page, MHD_RESPMEM_PERSISTENT)
		->header("Content-Type", "text/html")
		->cors()
		->flush(MHD_HTTP_FORBIDDEN);
}