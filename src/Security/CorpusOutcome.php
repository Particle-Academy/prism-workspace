<?php

declare(strict_types=1);

namespace Prism\Workspace\Security;

enum CorpusOutcome: string
{
    /** Refused, with the code the corpus names. The only passing outcome. */
    case Refused = 'refused';

    /**
     * Refused, but as something else.
     *
     * A failure, not a warning. Which refusal fires is what a consumer alerts
     * on: "an agent tried to leave its workspace" and "the name has a trailing
     * dot" are different pages in the middle of the night.
     */
    case WrongCode = 'wrong-code';

    /** Accepted. The boundary did not hold. */
    case Accepted = 'accepted';

    /** Something else went wrong, which is not a pass either. */
    case Errored = 'errored';
}
