from domains.check.jurisdictions import get_country_name, match


class TestMatch:
    def test_match__matches_a_subdomain_of_a_provider(self):
        assert (
            match("contoso-com.mail.protection.outlook.com")["name"] == "Microsoft 365"
        )

    def test_match__requires_a_label_boundary(self):
        assert match("notoutlook.com") is None


class TestGetCountryName:
    def test_get_country_name__returns_the_name_for_a_known_code(self):
        assert get_country_name("DE") == "Germany"
