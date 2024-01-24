from typing import Union
from typing_extensions import Annotated, Doc

from fastapi import Form
from pydantic import EmailStr


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
            Form(pattern="^\S+$", min_length=6, max_length=255),
            Doc(
                """
                username of admin [can't contain whitspace chars].

                for example: john.doe
                """
            )
        ],
        preferred_name: Annotated[
            Union[str, None],
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
            Form(min_length=6, max_length=255),
            Doc(
                """
                password of admin.

                for example: abc123!@#, p@ssword, p@55w0rd
                """
            )
        ],
        org_identifier: Annotated[
            str,
            Form(pattern="^\S+$", min_length=6, max_length=255),
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
        ],
        org_name: Annotated[
            Union[str, None],
            Form(min_length=6, max_length=255),
            Doc(
                """
                Name Of Organization of admin. if not provided it
                will take same value as org_identifier of admin.

                for example: "Foo Bar Inc."
                """
            )
        ] = None
    ):
        self.email = email
        self.username = username
        self.preferred_name = preferred_name or username
        self.password = password
        self.org_identifier = org_identifier
        self.org_name = org_name or org_identifier


class PrincipalUserWorkerDraftForm:
    def __init__(
        self,
        *,
        email: Annotated[
            EmailStr,
            Form(),
            Doc(
                """
                email of the user (Principal User Worker)
                """
            )
        ],
        username: Annotated[
            Union[str, None],
            Form(pattern="^\S+$", min_length=6, max_length=255),
            Doc(
                """
                username of user (Principal User Worker) [can't contain whitspace chars].

                for example: john.doe
                """
            )
        ] = None,
        password: Annotated[
            Union[str, None],
            Form(min_length=6, max_length=255),
            Doc(
                """
                password of user (Principal User Worker).

                for example: abc123!@#, p@ssword, p@55w0rd
                """
            )
        ] = None
    ):
        self.email = email
        self.username = username
        self.password = password


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
            Form(pattern="^\S+$", min_length=6, max_length=255),
            Doc(
                """
                username of service provider [can't contain whitspace chars].

                for example: jira
                """
            )
        ],
        org_name: Annotated[
            Union[str, None],
            Form(min_length=6, max_length=255),
            Doc(
                """
                Name Of Organization of Service Provider. if not
                provided it will take same value as username of
                Service Provider.

                for example: "Jira Inc."
                """
            )
        ] = None,
        password: Annotated[
            str,
            Form(min_length=6, max_length=255),
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
        self.org_name = org_name or username
        self.password = password

