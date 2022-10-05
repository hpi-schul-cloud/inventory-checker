import abc
import logging

from requests import HTTPError



class CVESource(metaclass=abc.ABCMeta):

    # Prometheus Gauge to report status
    @property
    @abc.abstractmethod
    def STATUS_REPORT(self):
        pass

    # Name of CVE source
    @property
    @abc.abstractmethod
    def NAME(self):
        pass

    @staticmethod
    @abc.abstractmethod
    def fetch_cves(invch):
        pass

    @classmethod
    def try_fetching_cves(cls, invch) -> bool:
        try:
            cls.fetch_cves(invch)
            cls.STATUS_REPORT.set(1)
            return True
        except HTTPError as http_error:
            logging.error(f"Fetching from {cls.NAME} CVE Source unsuccessfull. HTTP code: {http_error.response.status_code}")
            cls.STATUS_REPORT.set(0)
            return False
        except Exception as e:
            logging.error(f"Error while fetching {cls.NAME} CVE Source: ")
            logging.exception(e)
            cls.STATUS_REPORT.set(0)
            return False
