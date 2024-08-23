#include <cassert>
#include <memory>
#include <string>
#include <string_view>

class PasswordValidator {
  public:
    virtual bool Validate(std::string_view password) = 0;
    virtual ~PasswordValidator() = default;
};

class LengthValidator final : public PasswordValidator {
  public:
    explicit LengthValidator(unsigned int min_length) : length_(min_length) {}

    bool Validate(std::string_view password) override {
        return password.length() >= length_;
    }

  private:
    unsigned int length_;
};

class PasswordValidatorDecorator : public PasswordValidator {
  public:
    explicit PasswordValidatorDecorator(std::unique_ptr<PasswordValidator> validator) : inner_(std::move(validator)) {}

    bool Validate(std::string_view password) override {
        return inner_->Validate(password);
    }

  private:
    std::unique_ptr<PasswordValidator> inner_;
};

class DigitPasswordValidator final : public PasswordValidatorDecorator {
  public:
    explicit DigitPasswordValidator(std::unique_ptr<PasswordValidator> validator) : PasswordValidatorDecorator(std::move(validator)) {}

    bool Validate(std::string_view password) override {
        if (!PasswordValidatorDecorator::Validate(password)) {
            return false;
        }
        return password.find_first_of("0123456789") != std::string::npos;
    }
};

class CasePasswordValidator final : public PasswordValidatorDecorator {
  public:
    explicit CasePasswordValidator(std::unique_ptr<PasswordValidator> validator) : PasswordValidatorDecorator(std::move(validator)) {}

    bool Validate(std::string_view password) override {
        if (!PasswordValidatorDecorator::Validate(password)) {
            return false;
        }

        bool has_lower = false;
        bool has_upper = false;

        for (size_t i = 0; i < password.length() && !(has_upper && has_lower); ++i) {
            if (islower(password[i])) {
                has_lower = true;
            }
            else if (isupper(password[i])) {
                has_upper = true;
            }
        }

        return has_lower && has_upper;
    }
};

class SymbolPasswordValidator final : public PasswordValidatorDecorator {
  public:
    explicit SymbolPasswordValidator(std::unique_ptr<PasswordValidator> validator) : PasswordValidatorDecorator(std::move(validator)) {}

    bool Validate(std::string_view password) override {
        if (!PasswordValidatorDecorator::Validate(password)) {
            return false;
        }

        return password.find_first_of("!@#$%^&*(){}[]?<>") != std::string::npos;
    }
};

int main() {
    {
        auto validator = std::make_unique<LengthValidator>(8);

        assert(validator->Validate("abc123!@#"));
        assert(!validator->Validate("abc123"));
    }

    {
        auto validator = std::make_unique<DigitPasswordValidator>(std::make_unique<LengthValidator>(8));

        assert(validator->Validate("abc123!@#"));
        assert(!validator->Validate("abcde!@#"));
    }

    {
        auto validator = std::make_unique<CasePasswordValidator>(std::make_unique<DigitPasswordValidator>(std::make_unique<LengthValidator>(8)));

        assert(validator->Validate("Abc123!@#"));
        assert(!validator->Validate("abc123!@#"));
    }

    {
        auto validator = std::make_unique<SymbolPasswordValidator>(std::make_unique<CasePasswordValidator>(std::make_unique<DigitPasswordValidator>(std::make_unique<LengthValidator>(8))));

        assert(validator->Validate("Abc123!@#"));
        assert(!validator->Validate("Abc123567"));
    }
}
