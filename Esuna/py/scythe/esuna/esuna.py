import uuid
import fury

g_client = None

CATEGORY_WORKER = 4
ESUNA_MODULE_ID = uuid.UUID('3c9fa530-d5af-11ea-87b3-71900e1848d8')

def init(client, **kwargs):
    """

    :param client:
    :param kwargs:
    :return:
    """
    global g_client
    g_client = client
    return True


def run(message,  **kwargs):
    """

    :param bytes message:
    :param kwargs:
    :return bytes or None: None if post will happen asynchronously
    """
    result = fury.main()
    message = result.encode('utf-8')
    return message


def getinfo():
    """

    :return:
    """
    return { "type": CATEGORY_WORKER, "version" : {"major": 1, "minor": 0}, "id" : ESUNA_MODULE_ID}


def deinit(**kwargs):
    """

    :param kwargs:
    :return:
    """
    return True
