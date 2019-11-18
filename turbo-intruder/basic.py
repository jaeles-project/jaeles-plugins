def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=2,
                           requestsPerConnection=10,
                           pipeline=False,
                           maxQueueSize=1,
                           timeout=20,
                           maxRetriesPerRequest=3
                           )
    engine.start()
    engine.queue(target.req)


def handleResponse(req, interesting):
    # just mark the result for easily parse
    print("=-+-================")
    resTime = str(float(req.time) / 1000)
    info = "[Info] {0} {1} {2}".format(req.status, req.length, resTime)
    print(info)
    print("------------------+=")
    print(req.request)
    print("------------------+=")
    print(req.response)
    print("=-+-================")
