- [ ] **Grade SGE-DMARC-R04 behind a third-party MX on DMARC, not on the spoof
  action.** When a domain's MX points to a service in front of Exchange
  Online (for example `mx1.gateway.example.net`) and the platform does not
  apply DMARC on that route, a *Quarantine* spoof-intelligence action is read
  as *met*. On that route the platform never identifies a message as failing
  DMARC, so the row is graded on a different test from the one the
  requirement names, while SGE-DMARC-02 reads *not measured* on the same
  facts. The gateway's unknown handling is treated three ways today: a policy
  that ignores DMARC is *not met*, a platform failure is *not measured*, and a
  spoof-action pass is *met*. Decide one treatment (*not measured*, or a pass
  qualified as the spoof action's), then align `sge._eval_dmarc_quarantine`,
  `test_where_dmarc_is_not_applied_the_spoof_action_decides`,
  `docs/SGE-NOTE.md` and `docs/COLLECTORS.md`.
