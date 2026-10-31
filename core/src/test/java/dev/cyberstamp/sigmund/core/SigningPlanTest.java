package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class SigningPlanTest {

    private static final SigningInfo SQ_V4 = new SigningInfo("sq", "AAAA", "EdDSA", null, "pgp4");
    private static final SigningInfo SQ_V6 = new SigningInfo("sq", "BBBB", "ML-DSA-87+Ed448", null, "pgp6");
    private static final SigningInfo BC_V4 = new SigningInfo("bc", "CCCC", "EdDSA", null, "pgp4");

    @Nested
    class Selection {

        @Test
        void aRequestedTypeSelectsOnlyItsKeys() {
            SigningPlan plan = SigningPlan.of(List.of(tool("sq", SQ_V4, SQ_V6)), List.of("pgp4"));

            assertThat(plan.keys()).containsExactly(SQ_V4);
            assertThat(plan.problems()).isEmpty();
        }

        @Test
        void nothingRequestedSignsWithEveryKey() {
            SigningPlan plan = SigningPlan.of(List.of(tool("sq", SQ_V4, SQ_V6)), List.of());

            assertThat(plan.keys()).containsExactly(SQ_V4, SQ_V6);
            assertThat(plan.problems()).isEmpty();
        }

        @Test
        void keysFollowToolOrder() {
            SigningPlan plan = SigningPlan.of(List.of(tool("bc", BC_V4), tool("sq", SQ_V4, SQ_V6)),
                    List.of());

            assertThat(plan.keys()).containsExactly(BC_V4, SQ_V4, SQ_V6);
            assertThat(plan.keys()).extracting(SigningInfo::toolName).containsExactly("bc", "sq", "sq");
        }

        @Test
        void aDefaultKeyOfTheWrongTypeDropsItsTool() {
            SigningInfo sqDefaultV6 = new SigningInfo("sq", null, "Ed448", null, "pgp6");
            SigningPlan plan = SigningPlan.of(List.of(tool("bc", BC_V4), tool("sq", sqDefaultV6)),
                    List.of("pgp4"));

            assertThat(plan.keys()).containsExactly(BC_V4);
            assertThat(plan.problems()).isEmpty();
        }

        @Test
        void aToolReportingNoKeySignsOnceWhenNothingIsRequested() {
            SigningPlan plan = SigningPlan.of(List.of(tool("custom")), List.of());

            assertThat(plan.keys()).containsExactly(new SigningInfo("custom", null, null, null, null));
            assertThat(plan.problems()).isEmpty();
        }
    }

    @Nested
    class MissingType {

        @Test
        void aRequestedTypeNoKeyCoversIsAProblem() {
            SigningPlan plan = SigningPlan.of(
                    List.of(tool("bc", BC_V4), tool("sq", new SigningInfo("sq", "DDDD", "EdDSA", null, "pgp4"))),
                    List.of("pgp4", "pgp6"));

            assertThat(plan.problems()).containsExactly(
                    "no signing key for requested credential type pgp6; keys in the run: bc pgp4, sq pgp4");
        }

        @Test
        void sigstoreWithOnlyOpenPgpToolsIsAProblem() {
            SigningPlan plan = SigningPlan.of(List.of(tool("bc", BC_V4)), List.of("sigstore"));

            assertThat(plan.keys()).isEmpty();
            assertThat(plan.problems()).containsExactly(
                    "no signing key for requested credential type sigstore; keys in the run: bc pgp4");
        }

        @Test
        void requireSignableJoinsTheProblems() {
            SigningPlan plan = SigningPlan.of(List.of(tool("bc", BC_V4)), List.of("pgp6", "sigstore"));

            assertThatThrownBy(plan::requireSignable)
                    .isInstanceOf(SigmundException.class)
                    .hasMessage("no signing key for requested credential type pgp6; keys in the run: bc pgp4; "
                            + "no signing key for requested credential type sigstore; keys in the run: bc pgp4");
        }

        @Test
        void requireSignablePassesWithoutProblems() {
            SigningPlan plan = SigningPlan.of(List.of(tool("bc", BC_V4)), List.of("pgp4"));

            assertThat(plan.problems()).isEmpty();
            assertThatCode(plan::requireSignable).doesNotThrowAnyException();
        }
    }

    @Nested
    class ToolWithoutARequestedKey {

        @Test
        void dropsOutWithoutAProblem() {
            SigningInfo gpgV4 = new SigningInfo("gpg", "EEEE", "RSA", null, "pgp4");
            SigningPlan plan = SigningPlan.of(List.of(tool("gpg", gpgV4), tool("sq", SQ_V6)), List.of("pgp6"));

            assertThat(plan.keys()).containsExactly(SQ_V6);
            assertThat(plan.problems()).isEmpty();
        }

        @Test
        void isNamedInTheMissingTypeProblemWhenNoToolCoversTheType() {
            SigningInfo gpgV4 = new SigningInfo("gpg", "EEEE", "RSA", null, "pgp4");
            SigningPlan plan = SigningPlan.of(List.of(tool("gpg", gpgV4)), List.of("pgp6"));

            assertThat(plan.problems()).containsExactly(
                    "no signing key for requested credential type pgp6; keys in the run: gpg pgp4");
        }
    }

    @Nested
    class KeyOfAnotherTool {

        @Test
        void isRejected() {
            assertThatThrownBy(() -> SigningPlan.of(List.of(tool("gpg", BC_V4)), List.of()))
                    .isInstanceOf(SigmundException.class)
                    .hasMessage("tool 'gpg' reported a signing key of tool 'bc'");
        }
    }

    @Nested
    class UnreadableType {

        @Test
        void anUnreadableTypeIsAProblemWhenTypesAreRequested() {
            SigningInfo bcUnknown = new SigningInfo("bc", "FFFF", null, null, null);
            SigningPlan plan = SigningPlan.of(List.of(tool("bc", bcUnknown)), List.of("pgp4"));

            assertThat(plan.problems()).first().isEqualTo(
                    "tool 'bc': the credential type of signing key FFFF cannot be read, "
                            + "and the run requests credential types [pgp4]");
        }

        @Test
        void anUnreadableDefaultKeyIsNamedAsTheDefaultKey() {
            SigningInfo bcUnknown = new SigningInfo("bc", null, null, null, null);
            SigningPlan plan = SigningPlan.of(List.of(tool("bc", bcUnknown)), List.of("pgp4"));

            assertThat(plan.problems()).first().isEqualTo(
                    "tool 'bc': the credential type of signing key default key cannot be read, "
                            + "and the run requests credential types [pgp4]");
        }

        @Test
        void anUnreadableTypeSignsWhenNothingIsRequested() {
            SigningInfo bcUnknown = new SigningInfo("bc", null, null, null, null);
            SigningPlan plan = SigningPlan.of(List.of(tool("bc", bcUnknown)), List.of());

            assertThat(plan.keys()).containsExactly(bcUnknown);
            assertThat(plan.problems()).isEmpty();
        }
    }

    @Nested
    class Order {

        @Test
        void problemsAreOrderedByRule() {
            SigningInfo bcUnknown = new SigningInfo("bc", null, null, null, null);
            SigningInfo gpgV4 = new SigningInfo("gpg", "EEEE", "RSA", null, "pgp4");
            SigningPlan plan = SigningPlan.of(List.of(tool("gpg", gpgV4), tool("bc", bcUnknown)),
                    List.of("pgp6"));

            assertThat(plan.problems()).hasSize(2);
            assertThat(plan.problems().get(0)).startsWith("tool 'bc'");
            assertThat(plan.problems().get(1)).startsWith("no signing key for requested credential type pgp6");
        }
    }

    private static SignatureTool tool(String name, SigningInfo... keys) {
        return new SignatureTool() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public boolean isAvailable() {
                return true;
            }

            @Override
            public boolean canSign() {
                return true;
            }

            @Override
            public List<SigningInfo> signingInfo() {
                return List.of(keys);
            }

            @Override
            public SignatureFormat signatureFormat() {
                throw new UnsupportedOperationException();
            }

            @Override
            public Set<String> supportedCredentialTypes() {
                return Set.of("pgp4", "pgp6");
            }

            @Override
            public boolean canVerify(Claim claim) {
                return false;
            }

            @Override
            public SignResult sign(Path artifact, Path output, SigningInfo key) {
                throw new UnsupportedOperationException();
            }

            @Override
            public VerifyResult verify(Path artifact, Claim claim) {
                throw new UnsupportedOperationException();
            }

            @Override
            public List<Credential> extractCredentials(VerifyResult result) {
                return List.of();
            }
        };
    }
}
