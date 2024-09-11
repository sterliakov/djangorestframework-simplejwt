from typing import TYPE_CHECKING, Any, Dict, Optional, Union

from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions, status

if TYPE_CHECKING:
    from django.utils.functional import _StrPromise


class TokenError(Exception):
    pass


class TokenBackendError(Exception):
    pass


class DetailDictMixin:
    default_detail: str
    default_code: str

    def __init__(
        self,
        detail: Union[Dict[str, Any], str, None, "_StrPromise"] = None,
        code: Optional[str] = None,
    ) -> None:
        """
        Builds a detail dictionary for the error to give more information to API
        users.
        """
        detail_dict: Dict[str, Union[str, "_StrPromise"]] = {
            "detail": self.default_detail,
            "code": self.default_code,
        }

        if isinstance(detail, dict):
            detail_dict.update(detail)
        elif detail is not None:
            detail_dict["detail"] = detail

        if code is not None:
            detail_dict["code"] = code

        super().__init__(detail_dict)  # type: ignore


class AuthenticationFailed(DetailDictMixin, exceptions.AuthenticationFailed):
    pass


class InvalidToken(AuthenticationFailed):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = _("Token is invalid or expired")
    default_code = "token_not_valid"
