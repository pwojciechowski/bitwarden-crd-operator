from utils.utils import (
    BitwardenCommandException,
    get_secret_from_bitwarden,
    get_attachment,
    parse_fields_scope,
    parse_login_scope,
)


class BitwardenLookupHandler:
    def __init__(self, logger) -> None:
        self.logger = logger

    def bitwarden_lookup(self, id, scope, field):
        # A failed attachment call returns None. Raise instead, so the template
        # fails to render and the Secret keeps its value rather than "None".
        # get_secret_from_bitwarden raises on failure itself.
        if scope == "attachment":
            attachment = get_attachment(self.logger, id, field)
            if attachment is None:
                raise BitwardenCommandException(
                    f"Lookup of attachment {field!r} on item {id!r} failed"
                )
            return attachment
        _secret_json = get_secret_from_bitwarden(self.logger, id)
        if scope == "login":
            value = parse_login_scope(_secret_json, field)
        elif scope == "fields":
            value = parse_fields_scope(_secret_json, field)
        else:
            raise BitwardenCommandException(f"Unknown lookup scope {scope!r}")
        if value is None:
            raise BitwardenCommandException(
                f"Item {id!r} has no {scope} value {field!r}"
            )
        return value
