import os


class zwlScan:

    def __init__(self):
        self.base_path = os.path.dirname(os.path.realpath(__file__))
        self.work_path = os.getcwd()
        self.args = Argument(self.base_path, self.work_path)
        self.control = Controller(args=self.args)
        self.control.start()


def main():
    zwlScan()


if __name__ == "__main__":
    from lib.io.Argument import Argument
    from lib.controller.Controller import Controller
    main()
