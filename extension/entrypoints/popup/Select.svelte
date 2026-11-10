<script lang="ts">
  // Свой выпадающий список вместо системного <select>: в стиле окна Keywarden.
  import { fly } from 'svelte/transition';
  import { cubicOut } from 'svelte/easing';
  import type { Snippet } from 'svelte';

  type Option = { value: string; label: string; depth?: number; count?: number };
  let {
    value = '',
    options,
    onchange,
    icon,
  }: { value?: string; options: Option[]; onchange: (v: string) => void; icon?: Snippet } = $props();

  let open = $state(false);
  let active = $state(0);
  let root = $state<HTMLElement | null>(null);
  const current = $derived(options.find((o) => o.value === value) ?? options[0]);
  const still = matchMedia('(prefers-reduced-motion: reduce)').matches;

  function toggle() {
    open = !open;
    active = Math.max(0, options.findIndex((o) => o.value === value));
  }
  function pick(v: string) {
    open = false;
    if (v !== value) onchange(v);
  }
  function onkey(e: KeyboardEvent) {
    if (!open && (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ')) {
      e.preventDefault();
      return toggle();
    }
    if (!open) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      open = false;
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      active = (active + 1) % options.length;
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      active = (active - 1 + options.length) % options.length;
    } else if (e.key === 'Enter') {
      e.preventDefault();
      pick(options[active].value);
    }
  }
</script>

<svelte:window onmousedown={(e) => open && root && !root.contains(e.target as Node) && (open = false)} />

<div class="sel" bind:this={root}>
  <button class="trigger" class:on={open || !!value} aria-haspopup="listbox" aria-expanded={open} onclick={toggle} onkeydown={onkey}>
    {#if icon}{@render icon()}{/if}
    <span class="cur">{current?.label}</span>
    <svg class="chev" class:up={open} viewBox="0 0 24 24"><path d="m6 9 6 6 6-6" /></svg>
  </button>
  {#if open}
    <div class="list" role="listbox" transition:fly={{ y: -4, duration: still ? 0 : 140, easing: cubicOut }}>
      {#each options as o, i (o.value)}
        <button
          role="option"
          aria-selected={o.value === value}
          class="opt"
          class:act={i === active}
          style:padding-left={`${10 + (o.depth ?? 0) * 12}px`}
          onmouseenter={() => (active = i)}
          onclick={() => pick(o.value)}
        >
          <span class="lbl">{o.label}</span>
          {#if o.count !== undefined}<span class="cnt">{o.count}</span>{/if}
          {#if o.value === value}
            <svg class="tick" viewBox="0 0 24 24"><path d="m5 12 5 5 9-10" /></svg>
          {/if}
        </button>
      {/each}
    </div>
  {/if}
</div>

<style>
  .sel {
    position: relative;
    min-width: 0;
  }
  .trigger {
    all: unset;
    box-sizing: border-box;
    width: 100%;
    height: 32px;
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 0 8px 0 9px;
    border-radius: 9px;
    border: 1px solid #2c2d33;
    background: #1b1b1f;
    color: #8e8e98;
    font: 500 12px Inter, system-ui, sans-serif;
    cursor: pointer;
    transition: border-color 0.12s, background 0.12s;
  }
  .trigger:hover {
    background: #222227;
  }
  .trigger.on {
    color: #ececef;
  }
  .trigger:focus-visible {
    border-color: #5d5f6a;
  }
  .trigger :global(svg) {
    width: 13px;
    height: 13px;
    flex: none;
    fill: none;
    stroke: currentColor;
    stroke-width: 1.8;
    stroke-linecap: round;
    stroke-linejoin: round;
  }
  .cur {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .chev {
    color: #8e8e98;
    transition: transform 0.16s cubic-bezier(0.22, 1, 0.36, 1);
  }
  .chev.up {
    transform: rotate(180deg);
  }
  .list {
    position: absolute;
    top: calc(100% + 6px);
    left: 0;
    min-width: 100%;
    width: max-content;
    max-width: 260px;
    max-height: 260px;
    overflow-y: auto;
    z-index: 30;
    padding: 4px;
    border-radius: 12px;
    border: 1px solid #2c2d33;
    background: #1f1f23;
    box-shadow: 0 14px 32px #000a;
  }
  .opt {
    all: unset;
    box-sizing: border-box;
    width: 100%;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 7px 10px;
    border-radius: 8px;
    color: #ececef;
    font: 400 12px Inter, system-ui, sans-serif;
    cursor: pointer;
  }
  .opt.act {
    background: #2a2a30;
  }
  .lbl {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .cnt {
    color: #8e8e98;
    font-size: 11px;
  }
  .tick {
    width: 13px;
    height: 13px;
    fill: none;
    stroke: #a18bff;
    stroke-width: 2.4;
    stroke-linecap: round;
    stroke-linejoin: round;
  }
</style>
