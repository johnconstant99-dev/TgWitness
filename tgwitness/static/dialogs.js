// Panel dialogs in place of window.prompt/confirm, which embedded and some mobile browsers refuse.
// Each call returns a promise: confirm → true/false, prompt → text or null, typed → true when the
// person typed the expected name.
(() => {
  const t = (text, vars) => (typeof tr === "function" ? tr(text, vars) : text);

  function open({title, message, danger, confirmText, field, expected, choices, choicesLabel}) {
    return new Promise(resolve => {
      const dialog = document.createElement("dialog");
      dialog.className = "export-dialog panel-dialog";
      dialog.setAttribute("aria-labelledby", "panel-dialog-title");
      const form = document.createElement("form");
      form.method = "dialog";
      const heading = document.createElement("h2");
      heading.id = "panel-dialog-title";
      heading.textContent = title || t(danger ? "Please confirm" : "Confirm");
      form.append(heading);
      for (const part of String(message || "").split("\n\n")) {
        const paragraph = document.createElement("p");
        paragraph.className = "panel-dialog-text";
        paragraph.textContent = part;
        form.append(paragraph);
      }
      let input = null;
      if (field) {
        const label = document.createElement("label");
        label.className = "panel-dialog-field";
        label.textContent = field.label || "";
        input = document.createElement("input");
        input.value = field.value || "";
        input.maxLength = field.maxLength || 200;
        input.autocomplete = "off";
        if (field.placeholder) input.placeholder = field.placeholder;
        label.append(input);
        form.append(label);
      }
      let boxes = null;
      if (choices?.length) {
        const set = document.createElement("fieldset");
        set.className = "panel-dialog-choices";
        const legend = document.createElement("legend");
        legend.textContent = choicesLabel || "";
        set.append(legend);
        boxes = choices.map(choice => {
          const row = document.createElement("label"), box = document.createElement("input");
          row.className = "check-label";
          box.type = "checkbox"; box.value = choice.value; box.checked = !!choice.checked;
          row.append(box, document.createTextNode(" " + choice.label));
          set.append(row);
          return box;
        });
        form.append(set);
      }
      const actions = document.createElement("div");
      actions.className = "export-dialog-actions";
      const cancel = document.createElement("button");
      cancel.type = "button";
      cancel.className = "secondary";
      cancel.textContent = t("Cancel");
      const accept = document.createElement("button");
      accept.type = "submit";
      accept.className = danger ? "danger" : "primary";
      accept.textContent = confirmText || t("OK");
      actions.append(cancel, accept);
      form.append(actions);
      dialog.append(form);

      const value = () => (input ? input.value.trim() : "");
      const ready = () => {
        if (expected !== undefined) accept.disabled = value() !== expected;
        else if (field?.required) accept.disabled = !value();
      };
      let result = null;
      input?.addEventListener("input", ready);
      cancel.addEventListener("click", () => dialog.close());
      form.addEventListener("submit", event => {
        if (accept.disabled) { event.preventDefault(); return; }
        result = input ? value() : choices ? (boxes || []).filter(box => box.checked).map(box => box.value) : true;
      });
      dialog.addEventListener("close", () => {
        dialog.remove();
        if (expected !== undefined) resolve(result === expected);
        else if (choices) resolve(Array.isArray(result) ? result : null);
        else resolve(input ? result : result === true);
      });
      document.body.append(dialog);
      ready();
      dialog.showModal();
      (input || (danger ? cancel : accept)).focus();
    });
  }

  window.TgWitnessDialogs = {
    confirm: (message, options = {}) => open({...options, message}),
    prompt: (message, options = {}) => open({...options, message, field: {label: options.label, value: options.value,
      placeholder: options.placeholder, maxLength: options.maxLength, required: options.required !== false}}),
    typed: (message, expected, options = {}) => open({...options, message, danger: true, expected,
      field: {label: options.label || t("Type the name to confirm"), placeholder: expected, maxLength: 300}}),
    choose: (message, options = {}) => open({...options, message, choices: options.choices || []}),
  };
})();
