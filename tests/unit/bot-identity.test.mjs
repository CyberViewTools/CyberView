// Automated commits are made as cyberview-bot, never as the assistant a cloud session is signed in as (CLAUDE.md, Authorship).
import { test } from "node:test";
import assert from "node:assert/strict";
import { BOT, isAssistantEmail } from "../../scripts/lib/repo.mjs";

test("an unset or anthropic.com identity is replaced by the bot", () => {
  assert.equal(isAssistantEmail(""), true);
  assert.equal(isAssistantEmail(undefined), true);
  assert.equal(isAssistantEmail("noreply@anthropic.com"), true);
  assert.equal(isAssistantEmail(" NoReply@Anthropic.com "), true);
});

test("a person's own identity is left alone", () => {
  assert.equal(isAssistantEmail("xanderhutch@users.noreply.github.com"), false);
  assert.equal(isAssistantEmail("cyberview-bot@users.noreply.github.com"), false);
  assert.equal(isAssistantEmail("someone@anthropic.com.example.org"), false);
});

test("the bot identity is cyberview-bot", () => {
  assert.deepEqual({ ...BOT }, { name: "cyberview-bot", email: "cyberview-bot@users.noreply.github.com" });
});
