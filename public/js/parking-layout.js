(function (root) {
  "use strict";

  // Keep the original buttons (and their slot IDs/listeners). Dividers are
  // decorative elements, never parking records or selectable spaces.
  function apply(grid) {
    if (!grid || grid.classList.contains("parking-plan")) return;
    const buttons = Array.from(grid.children).filter(node => node.tagName === "BUTTON");
    if (!buttons.length) return;
    const leftSideOnly = String(grid.dataset.parkingZone || "").trim().toLowerCase() === "hangar parking zone";
    const spacesPerRow = leftSideOnly ? 1 : 2;
    const doc = grid.ownerDocument;
    const element = (tag, className, text) => {
      const node = doc.createElement(tag);
      node.className = className;
      if (text) node.textContent = text;
      return node;
    };
    const lane = () => {
      const node = element("span", "parking-plan-lane");
      node.setAttribute("aria-hidden", "true");
      return node;
    };

    buttons.sort((a, b) => String(a.dataset.slotCode || "").localeCompare(
      String(b.dataset.slotCode || ""), undefined, { numeric: true }
    ));
    const fragment = doc.createDocumentFragment();
    const key = element("div", "parking-plan-key");
    key.innerHTML = '<span><i class="parking-plan-key-bay" aria-hidden="true"></i>Parking space</span>' +
      (leftSideOnly ? '<span>Left-side parking</span>' : '<span><i class="parking-plan-key-divider" aria-hidden="true"></i>Divider</span>');
    fragment.append(key);
    const heading = element("div", "parking-plan-heading", "Drive lane");
    fragment.append(heading);

    for (let index = 0; index < buttons.length; index += spacesPerRow) {
      if (!leftSideOnly && index > 0 && index % 4 === 0) {
        const dividerRow = element("div", "parking-plan-row parking-plan-divider-row");
        dividerRow.setAttribute("aria-hidden", "true");
        dividerRow.append(element("span", "parking-plan-divider", "Divider"), lane(),
          element("span", "parking-plan-divider", "Divider"));
        fragment.append(dividerRow);
      }
      const row = element("div", "parking-plan-row");
      for (let side = 0; side < 2; side++) {
        if (side === 1) row.append(lane());
        const button = leftSideOnly && side === 1 ? null : buttons[index + side];
        if (!button) {
          const blank = element("span", "parking-plan-empty");
          blank.setAttribute("aria-hidden", "true");
          row.append(blank);
          continue;
        }
        const state = ["available", "occupied", "disabled"].find(value =>
          button.classList.contains(value) || button.classList.contains(`state-${value}`)
        ) || "disabled";
        const label = button.dataset.parkingLabel || state.charAt(0).toUpperCase() + state.slice(1);
        const selected = button.classList.contains("selected") || button.classList.contains("is-selected");
        button.classList.add("parking-plan-bay");
        button.dataset.parkingState = state;
        button.dataset.parkingVisualState = state === "available" && button.dataset.slotType === "reserved" ? "reserved" : state;
        button.setAttribute("aria-pressed", String(selected));
        // Occupancy stays explicit even when the secondary line is a plate,
        // a reservation, or a maintenance reason instead of a status label.
        Array.from(button.children).slice(1).forEach(child => {
          if (child.textContent.trim().toLowerCase() === state) child.hidden = true;
        });
        const badge = element("span", "parking-plan-state");
        const icon = element("span", "parking-plan-state-icon ph " + { available: "ph-check-circle", occupied: "ph-car", disabled: "ph-prohibit" }[state]);
        icon.setAttribute("aria-hidden", "true");
        badge.append(icon, doc.createTextNode(label));
        button.append(badge);
        row.append(button);
      }
      fragment.append(row);
    }
    grid.replaceChildren(fragment);
    grid.classList.add("parking-plan");
  }

  root.NaapParkingLayout = { apply };
}(window));
