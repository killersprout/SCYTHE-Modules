import uuid
import silence

g_client = None
CATEGORY_WORKER = 4
DESPELL_MODULE_ID = uuid.UUID('3c6db110-d280-11ea-bd1f-e7e25f4a05db')


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
    # Get result of main's return
    result = silence.main()
    message = result.encode('utf-8')
    return message
   


def getinfo():
    """

    :return:
    """
    return { "type": CATEGORY_WORKER, "version" : {"major": 1, "minor": 0}, "id" : DESPELL_MODULE_ID}


def deinit(**kwargs):
    """

    :param kwargs:
    :return:
    """
    return True

