from typing import Annotated, Literal
from typing_extensions import Doc

from fastapi import Form
from pydantic import EmailStr

from src.types import UserType

class PrincipalUserAdminRegistrationForm:
    def __init__(
        self,
        *,
        email: Annotated[
            EmailStr,
            Form(),
            Doc(
                """
                email of admin.

                for example: john.doe@example.com
                """
            )
        ],
        username: Annotated[
            str,
            Form(pattern=r"^\S+$", min_length=6, max_length=255),
            Doc(
                """
                username of admin [can't contain whitspace chars].

                for example: john.doe
                """
            )
        ],
        preferred_name: Annotated[
            str | None,
            Form(),
            Doc(
                """
                preferred name of admin, if not provided it will take
                same value as username of admin.

                for example: "John Doe"
                """
            )
        ] = None,
        password: Annotated[
            str,
            Form(min_length=8, max_length=255),
            Doc(
                """
                password of admin.

                for example: abc123!@#, p@ssword, p@55w0rd
                """
            )
        ],
        org_identifier: Annotated[
            str,
            Form(pattern=r"^\S+$", min_length=6, max_length=255),
            Doc(
                """
                org_identifier is used for uniquely identify the
                organization of user.
                
                for example:
                Name of Organization of Admin: "Foo Bar Inc."
                org_identifier: "foobar" or "foo.bar" or any other
                                value that does not contain whitespace.
                """
            )
        ]
    ):
        self.email = email
        self.username = username
        self.preferred_name = preferred_name or username
        self.password = password
        self.org_identifier = org_identifier


class PrincipalUserDraftForm:
    def __init__(
        self,
        *,
        email: Annotated[
            EmailStr,
            Form(),
            Doc(
                """
                email of the user (Principal User)
                """
            )
        ],
        username: Annotated[
            str,
            Form(pattern=r"^\S+$", min_length=6, max_length=255),
            Doc(
                """
                username of user (Principal User) [can't contain whitspace chars].

                for example: john.doe
                """
            )
        ],
        password: Annotated[
            str,
            Form(min_length=8, max_length=255),
            Doc(
                """
                password of user (Principal User).

                for example: abc123!@#, p@ssword, p@55w0rd
                """
            )
        ],
        user_type: Annotated[
            Literal[UserType.ADMIN_USER, UserType.WORKER_USER],
            Form(),
            Doc(
                """
                type of user: admin or worker
                """
            )
        ]
    ):
        self.email = email
        self.username = username
        self.password = password
        self.user_type = user_type


class ServiceProviderRegistrationForm:
    def __init__(
        self,
        *,
        email: Annotated[
            EmailStr,
            Form(),
            Doc(
                """
                email of service provider

                for example: oidc@jira.atlassian.com
                """
            )
        ],
        username: Annotated[
            str,
            Form(pattern=r"^\S+$", min_length=6, max_length=255),
            Doc(
                """
                username of service provider [can't contain whitspace chars].

                for example: jira
                """
            )
        ],
        password: Annotated[
            str,
            Form(min_length=8, max_length=255),
            Doc(
                """
                password of admin.

                for example: abc123!@#, p@ssword, p@55w0rd
                """
            )
        ]
    ):
        self.email = email
        self.username = username
        self.password = password

